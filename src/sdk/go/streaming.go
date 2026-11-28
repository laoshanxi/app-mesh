// streaming.go
package appmesh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// ErrStreamTimeout wraps the error Next returns when the stream hits its
// server-side timeout (terminal reason "timeout").
var ErrStreamTimeout = errors.New("stream timed out")

// sseEndClosed marks a stream the peer cut without a terminal end frame.
const sseEndClosed = "closed"

// SseEnd is the terminal marker of an SSE stream: every stream emits exactly
// one end frame whose reason says how it ended.
type SseEnd struct {
	Reason   string // exit | removed | timeout | eof | final | disconnected | error | closed
	ExitCode *int   // output streams: process exit code when Reason is "exit"
	Position *int64 // output streams: final stdout byte cursor
	Status   *int   // task streams: HTTP status carried by an error end frame
	Message  string // task streams: error message
	Result   string // task streams: the final result payload (what RunTask returns)
}

// SseStream delivers the chunks of one daemon SSE stream (FollowOutput,
// RunTaskStream, StreamRun). Next returns each chunk, io.EOF on a natural
// end, an error wrapping ErrStreamTimeout on a "timeout" end and an *APIError
// on an "error" end. End exposes the terminal marker once Next reported the
// end; Close aborts an unfinished stream. Single-consumer, not safe for
// concurrent use; cancellation goes through the opening call's context.
type SseStream struct {
	body     io.ReadCloser
	scanner  *sseScanner
	task     bool    // task stream: the "final" frame fills End().Result
	end      *SseEnd // terminal marker, set when the stream ended
	err      error   // terminal or fatal error already reported by Next
	final    string  // task streams: result carried by the "final" frame
	hasFinal bool    // final was seen
	onFinish func()  // StreamRun: best-effort cleanup of the temporary run app
	closed   bool
}

// Next returns the next incremental chunk, blocking until one is produced.
// It returns io.EOF at the stream's end (read End for the marker) or the
// terminal error (ErrStreamTimeout / *APIError).
func (s *SseStream) Next() (string, error) {
	if s.closed {
		return "", errors.New("stream is closed")
	}
	if s.err != nil {
		return "", s.err
	}
	if s.end != nil {
		return "", io.EOF
	}
	for {
		event, data, ok, err := s.scanner.next()
		if err != nil {
			return "", s.terminate(fmt.Errorf("read stream failed: %w", err))
		}
		if !ok {
			// Peer cut the stream without a terminal end frame.
			s.setEnd(&SseEnd{Reason: sseEndClosed})
			return "", io.EOF
		}
		switch event {
		case "stdout":
			var payload struct {
				Output string `json:"output"`
			}
			if err := decodeSSEData(data, &payload); err != nil {
				return "", s.terminate(fmt.Errorf("malformed SSE frame (stdout): %w", err))
			}
			return payload.Output, nil
		case "partial":
			var payload struct {
				Data string `json:"data"`
			}
			if err := decodeSSEData(data, &payload); err != nil {
				return "", s.terminate(fmt.Errorf("malformed SSE frame (partial): %w", err))
			}
			return payload.Data, nil
		case "final":
			var payload struct {
				Result string `json:"result"`
			}
			if err := decodeSSEData(data, &payload); err != nil {
				return "", s.terminate(fmt.Errorf("malformed SSE frame (final): %w", err))
			}
			s.final, s.hasFinal = payload.Result, true
		case "end":
			end, err := s.endFromData(data)
			if err != nil {
				return "", s.terminate(err)
			}
			s.setEnd(end)
			if terr := streamTerminalError(end); terr != nil {
				s.err = terr
				return "", terr
			}
			return "", io.EOF
		default:
			// Unknown named events carry no chunks.
		}
	}
}

// End returns the terminal marker, or nil while the stream is open. It is set
// once Next reported the end (io.EOF or the terminal error).
func (s *SseStream) End() *SseEnd {
	return s.end
}

// Close aborts the stream and releases its connection. An unfinished stream
// also runs its completion hook (StreamRun removes its temporary run app).
func (s *SseStream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.runFinish()
}

// setEnd records the terminal marker and releases the stream resources.
func (s *SseStream) setEnd(end *SseEnd) {
	s.end = end
	s.runFinish()
}

// terminate records a fatal stream error and releases the stream resources.
func (s *SseStream) terminate(err error) error {
	if s.err == nil {
		s.err = err
	}
	s.runFinish()
	return err
}

// runFinish closes the response body and runs the completion hook exactly once.
func (s *SseStream) runFinish() error {
	var err error
	if s.body != nil {
		err = s.body.Close()
		s.body = nil
	}
	if s.onFinish != nil {
		onFinish := s.onFinish
		s.onFinish = nil
		onFinish()
	}
	return err
}

// endFromData builds the terminal marker from an end frame payload; an empty
// body keeps the zero values (reason "closed").
func (s *SseStream) endFromData(data string) (*SseEnd, error) {
	end := &SseEnd{Reason: sseEndClosed}
	if data != "" {
		var payload struct {
			Reason   string `json:"reason"`
			ExitCode *int   `json:"exit_code"`
			Position *int64 `json:"position"`
			Status   *int   `json:"status"`
			Message  string `json:"message"`
		}
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			return nil, fmt.Errorf("malformed SSE frame (end): %w", err)
		}
		if payload.Reason != "" {
			end.Reason = payload.Reason
		}
		end.ExitCode, end.Position, end.Status, end.Message = payload.ExitCode, payload.Position, payload.Status,
			payload.Message
	}
	if s.hasFinal {
		end.Result = s.final
	}
	return end, nil
}

// decodeSSEData parses one frame payload; an empty body decodes to the zero value.
func decodeSSEData(data string, payload interface{}) error {
	if data == "" {
		return nil
	}
	return json.Unmarshal([]byte(data), payload)
}

// streamTerminalError maps a terminal end frame to its error: "timeout" wraps
// ErrStreamTimeout, "error" is a request error; natural reasons return nil.
func streamTerminalError(end *SseEnd) error {
	switch end.Reason {
	case "timeout":
		if end.Message == "" {
			return ErrStreamTimeout
		}
		return fmt.Errorf("%w: %s", ErrStreamTimeout, end.Message)
	case "error":
		message := end.Message
		if message == "" {
			message = "stream failed with an error"
		}
		if end.Status != nil {
			return newAPIError("stream", *end.Status, message)
		}
		return errors.New(message)
	case "exit", "removed", "eof", "final", "disconnected", sseEndClosed:
		return nil
	default:
		return fmt.Errorf("stream ended with unknown reason: %s", end.Reason)
	}
}

// sseScanner splits a text/event-stream body into frames like the Python
// iter_sse_events: ": ping" lines are heartbeats, one frame's data lines join
// with "\n", and an empty line dispatches the frame.
type sseScanner struct {
	reader *bufio.Reader
	event  string   // event name of the frame in progress ("message" when unset)
	data   []string // data lines of the frame in progress
}

// next returns the next complete frame; ok is false once the body is exhausted
// (a trailing partial frame without its empty line is dropped, as in Python).
func (s *sseScanner) next() (event string, data string, ok bool, err error) {
	if s.event == "" {
		s.event = "message" // zero value until a frame boundary resets it
	}
	for {
		line, readErr := s.reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return "", "", false, readErr
		}
		if line != "" {
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "":
				// Frame boundary: dispatch a named event or one carrying data.
				if s.event != "message" || len(s.data) > 0 {
					event, data = s.event, strings.Join(s.data, "\n")
					s.event, s.data = "message", nil
					return event, data, true, nil
				}
				s.event, s.data = "message", nil
			case strings.HasPrefix(line, ":"):
				// Heartbeat comment (": ping" every 15 seconds).
			case strings.HasPrefix(line, "event:"):
				s.event = strings.TrimSpace(line[len("event:"):])
			case strings.HasPrefix(line, "data:"):
				s.data = append(s.data, strings.TrimLeft(line[len("data:"):], " \t"))
			}
		}
		if readErr != nil {
			return "", "", false, nil // io.EOF: body exhausted
		}
	}
}

// sseRequester is implemented by transports able to open a streamed
// text/event-stream response: plain HTTP natively, framed TCP and WSS via a
// direct HTTPS side channel to the daemon REST listener (sseSideChannel).
type sseRequester interface {
	sseRequest(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string,
		body []byte) (int, io.ReadCloser, http.Header, error)
}

// openSseStream performs the SSE request on the underlying transport and wraps
// the response body in an SseStream. task marks a streaming task RPC whose
// "final" frame populates End().Result.
func (r *AppMeshClient) openSseStream(ctx context.Context, op string, method string, apiPath string,
	queries url.Values, body []byte, task bool) (*SseStream, error) {
	sseReq, ok := r.req.(sseRequester)
	if !ok {
		return nil, fmt.Errorf("%s is not supported by this transport", op)
	}
	code, respBody, _, err := sseReq.sseRequest(ctx, method, apiPath, queries, nil, body)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		raw, _ := io.ReadAll(respBody) // error responses are small
		respBody.Close()
		apiErr := newAPIError(op, code, string(raw))
		if (code == http.StatusNotFound || code == http.StatusMethodNotAllowed) && r.getForwardTo() != "" {
			// The agent forwards "host:port" to that port: an explicit TCP port lands the
			// stream on a listener without stream routes.
			apiErr.text += fmt.Sprintf("; the forward target %q names the target's TCP listener, which serves no"+
				" streams: use a bare host (or the target's agent REST port, 6060)", r.getForwardTo())
		}
		return nil, apiErr
	}
	return &SseStream{
		body:    respBody,
		scanner: &sseScanner{reader: bufio.NewReader(respBody)},
		task:    task,
	}, nil
}

// FollowOutput streams an application's stdout over SSE: replay from
// stdoutPosition, then (follow=true) live output until exit, removal or
// timeout; the server de-duplicates the replay/live boundary, so no position
// bookkeeping is needed. The stream is single-consumer; Close aborts early,
// and End holds the exit code and final position once Next returned io.EOF.
func (r *AppMeshClient) FollowOutput(appName string, stdoutPosition int64, processUuid string, follow bool,
	timeout int) (*SseStream, error) {
	return r.FollowOutputContext(context.Background(), appName, stdoutPosition, processUuid, follow, timeout)
}

// FollowOutputContext is FollowOutput with a context; canceling it aborts the stream.
func (r *AppMeshClient) FollowOutputContext(ctx context.Context, appName string, stdoutPosition int64,
	processUuid string, follow bool, timeout int) (*SseStream, error) {
	if appName == "" {
		return nil, fmt.Errorf("application name is required")
	}
	if timeout <= 0 {
		timeout = 3600
	}
	q := url.Values{}
	q.Set("stdout_position", strconv.FormatInt(stdoutPosition, 10))
	q.Set("follow", strconv.FormatBool(follow))
	q.Set("timeout", strconv.Itoa(timeout))
	if processUuid != "" {
		q.Set("process_uuid", processUuid)
	}
	return r.openSseStream(ctx, "follow output", http.MethodGet,
		fmt.Sprintf("/appmesh/app/%s/output/stream", appName), q, nil, false)
}

// RunTaskStream is the streaming RunTask: the worker's partials (SendTaskPartial)
// arrive via Next in order; End().Result holds the final payload after the
// "final" end. Timeout <= 0 means 300s; overrun wraps ErrStreamTimeout.
func (r *AppMeshClient) RunTaskStream(appName string, payload string, timeout int) (*SseStream, error) {
	return r.RunTaskStreamContext(context.Background(), appName, payload, timeout)
}

// RunTaskStreamContext is RunTaskStream with a caller-supplied context for cancellation.
func (r *AppMeshClient) RunTaskStreamContext(ctx context.Context, appName string, payload string,
	timeout int) (*SseStream, error) {
	if appName == "" {
		return nil, fmt.Errorf("application name is required")
	}
	if timeout <= 0 {
		timeout = 300
	}
	q := url.Values{}
	q.Set("timeout", strconv.Itoa(timeout))
	return r.openSseStream(ctx, "run task stream", http.MethodPost,
		fmt.Sprintf("/appmesh/app/%s/task/stream", appName), q, []byte(payload), true)
}

// StreamRun runs a one-shot app and streams its stdout as it is produced
// (RunAppAsync + FollowOutput + DeleteApp) instead of buffering like
// RunAppSync; the temporary run app is always removed at end or Close.
func (r *AppMeshClient) StreamRun(app Application, maxTime int, lifecycle int) (*SseStream, error) {
	return r.StreamRunContext(context.Background(), app, maxTime, lifecycle)
}

// StreamRunContext is StreamRun with a caller-supplied context controlling cancellation.
func (r *AppMeshClient) StreamRunContext(ctx context.Context, app Application, maxTime int,
	lifecycle int) (*SseStream, error) {
	run, err := r.runAppAsync(ctx, app, maxTime, lifecycle)
	if err != nil {
		return nil, err
	}
	// Follow until the later of the two windows: retention may outlive runtime.
	followTimeout := maxTime
	if lifecycle > followTimeout {
		followTimeout = lifecycle
	}
	// Best-effort cleanup of the temporary run app on the node it was started on.
	cleanup := func() {
		_, _ = r.deleteApp(context.Background(), run.AppName, Headers{headerTargetHost: run.ForwardTo})
	}
	stream, err := r.FollowOutputContext(ctx, run.AppName, 0, run.ProcUid, true, followTimeout)
	if err != nil {
		cleanup()
		return nil, err
	}
	stream.onFinish = cleanup
	return stream, nil
}

// SendInput injects bytes into the stdin of a running app registered with
// Stdin "pipe", returning the bytes written; a full pipe answers 412
// (*APIError) — retry with the remainder.
func (r *AppMeshClient) SendInput(appName string, data []byte, closePipe bool, processUuid string) (int, error) {
	return r.SendInputContext(context.Background(), appName, data, closePipe, processUuid)
}

// SendInputContext is SendInput with a caller-supplied context controlling cancellation.
func (r *AppMeshClient) SendInputContext(ctx context.Context, appName string, data []byte, closePipe bool,
	processUuid string) (int, error) {
	if appName == "" {
		return 0, fmt.Errorf("application name is required")
	}
	headers := map[string]string{"Content-Type": "application/octet-stream"}
	if closePipe {
		headers[headerInputClose] = "true"
	}
	var queries url.Values
	if processUuid != "" {
		queries = url.Values{}
		queries.Set("process_uuid", processUuid)
	}
	code, raw, _, err := r.req.SendContext(ctx, http.MethodPost, fmt.Sprintf("/appmesh/app/%s/input", appName),
		queries, headers, bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("send input request failed: %w", err)
	}
	if code != http.StatusOK {
		return 0, newAPIError("send input", code, string(raw))
	}
	var resp struct {
		BytesWritten int64 `json:"bytes_written"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, fmt.Errorf("failed to unmarshal send input response: %w", err)
	}
	return int(resp.BytesWritten), nil
}

// sseSideChannel opens SSE over a direct HTTPS connection to the daemon REST
// listener: the framed TCP/WSS transports cannot carry a chunked stream, so
// streams bypass framing like the WSS file data channel. A forwarded stream
// (forwardTarget set) dials agentBase, the agent REST listener, with
// X-Target-Host; without an agent base it fails instead of streaming locally.
type sseSideChannel struct {
	base          url.URL        // REST listener base (scheme + host:port)
	agentBase     url.URL        // agent REST listener base for forwarded streams
	forwardTarget string         // X-Target-Host value; empty streams locally
	token         string         // bearer for the direct request
	agent         string         // transport-specific User-Agent
	signer        *requestSigner // opt-in HMAC request signing (nil = off)
	clientCert    string         // client certificate file (PEM), empty disables
	clientKey     string         // client certificate key file
	caFile        string         // trusted CA file/dir, empty skips verification
}

// open performs the side-channel request and returns the response body unread;
// the caller must close it.
func (c sseSideChannel) open(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body []byte) (int, io.ReadCloser, http.Header, error) {
	if c.token == "" {
		return 0, nil, nil, fmt.Errorf("streaming requires a bearer token")
	}
	u := c.base
	if c.forwardTarget != "" {
		// A caller-supplied X-Target-Host ("" disables) wins, as on framed requests.
		if override, set := headers[headerTargetHost]; set {
			c.forwardTarget = override
		}
		if c.forwardTarget != "" {
			if c.agentBase.Host == "" {
				return 0, nil, nil, fmt.Errorf("%s through node forwarding (X-Target-Host: %s) is not supported by this"+
					" transport: the agent REST listener address is unknown", opForPath(apiPath), c.forwardTarget)
			}
			u = c.agentBase
		}
	}
	u.Path = path.Join(u.Path, apiPath)
	if len(queries) > 0 {
		if c.signer != nil {
			// A signed request must never rely on '+'-for-space (encodeQueryPercentOnly).
			u.RawQuery = encodeQueryPercentOnly(queries)
		} else {
			u.RawQuery = queries.Encode()
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set(headerAuthorization, headerBearerSpace+c.token)
	req.Header.Set(userAgentHeaderName, c.agent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.forwardTarget != "" {
		req.Header.Set(headerTargetHost, c.forwardTarget)
	}
	// Streamed endpoints sign the empty-string body hash (documented exemption).
	// The signature covers method, path, query and body hash, not the target host.
	if err := signHTTPRequest(req, queries, c.signer); err != nil {
		return 0, nil, nil, err
	}
	httpConn, err := newHTTPConnection(c.clientCert, c.clientKey, c.caFile)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to create HTTP connection: %w", err)
	}
	// A stream outlives the client's 2-minute timeout: share the transport but
	// drop the deadline; liveness is the 15s ping plus the caller's context.
	client := *httpConn.Client
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("stream request failed: %w", err)
	}
	return resp.StatusCode, resp.Body, resp.Header, nil
}
