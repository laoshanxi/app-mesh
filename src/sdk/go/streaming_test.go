package appmesh

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestStream wraps raw SSE wire text in an SseStream without any transport.
func newTestStream(raw string, task bool) *SseStream {
	body := io.NopCloser(strings.NewReader(raw))
	return &SseStream{body: body, scanner: &sseScanner{reader: bufio.NewReader(body)}, task: task}
}

func TestSseScannerParsesFramesAndSkipsPings(t *testing.T) {
	raw := ": ping\n\n" +
		"event: stdout\n" +
		"data: {\"output\":\"a\"}\n" +
		"\n" +
		"event: partial\n" +
		"data: line1\n" +
		"data: line2\n" +
		"\n" +
		"event: bare\n" + // named event without data dispatches with empty data
		"\n" +
		"data: trailing-without-boundary\n" // dropped, as in the Python SDK

	sc := &sseScanner{reader: bufio.NewReader(strings.NewReader(raw))}
	frames := [][2]string{}
	for {
		event, data, ok, err := sc.next()
		require.NoError(t, err)
		if !ok {
			break
		}
		frames = append(frames, [2]string{event, data})
	}
	require.Equal(t, [][2]string{
		{"stdout", `{"output":"a"}`},
		{"partial", "line1\nline2"},
		{"bare", ""},
	}, frames)
}

func TestSseStreamDeliversOutputChunksAndExitEnd(t *testing.T) {
	stream := newTestStream("event: stdout\ndata: {\"output\":\"token1 \"}\n\n"+
		"event: stdout\ndata: {\"position\":8,\"output\":\"token2\"}\n\n"+
		"event: end\ndata: {\"reason\":\"exit\",\"exit_code\":3,\"position\":14}\n\n", false)

	var chunks []string
	for {
		chunk, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		chunks = append(chunks, chunk)
	}
	require.Equal(t, []string{"token1 ", "token2"}, chunks)

	end := stream.End()
	require.NotNil(t, end)
	require.Equal(t, "exit", end.Reason)
	require.NotNil(t, end.ExitCode)
	require.Equal(t, 3, *end.ExitCode)
	require.NotNil(t, end.Position)
	require.EqualValues(t, 14, *end.Position)

	// Next keeps reporting the natural end once the marker is set.
	_, err := stream.Next()
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, stream.Close())
}

func TestSseStreamTaskPartialsFinalResultAndTimeoutEnd(t *testing.T) {
	stream := newTestStream("event: partial\ndata: {\"data\":\"to\"}\n\n"+
		"event: partial\ndata: {\"data\":\"ken\"}\n\n"+
		"event: final\ndata: {\"result\":\"{\\\"answer\\\": 42}\"}\n\n"+
		"event: end\ndata: {\"reason\":\"timeout\",\"message\":\"task window elapsed\"}\n\n", true)

	chunk, err := stream.Next()
	require.NoError(t, err)
	require.Equal(t, "to", chunk)
	chunk, err = stream.Next()
	require.NoError(t, err)
	require.Equal(t, "ken", chunk)

	_, err = stream.Next()
	require.ErrorIs(t, err, ErrStreamTimeout)
	require.Contains(t, err.Error(), "task window elapsed")

	end := stream.End()
	require.NotNil(t, end)
	require.Equal(t, "timeout", end.Reason)
	require.Equal(t, `{"answer": 42}`, end.Result)
}

func TestSseStreamErrorEndMapsToAPIError(t *testing.T) {
	stream := newTestStream("event: end\ndata: {\"reason\":\"error\",\"status\":500,\"message\":\"boom\"}\n\n", false)

	_, err := stream.Next()
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, 500, apiErr.StatusCode)
	require.Contains(t, apiErr.Message, "boom")
	require.Equal(t, "error", stream.End().Reason)
}

func TestSseStreamClosedWithoutEndFrame(t *testing.T) {
	stream := newTestStream("event: stdout\ndata: {\"output\":\"tail\"}\n\n", false)

	chunk, err := stream.Next()
	require.NoError(t, err)
	require.Equal(t, "tail", chunk)

	_, err = stream.Next()
	require.ErrorIs(t, err, io.EOF)
	require.NotNil(t, stream.End())
	require.Equal(t, sseEndClosed, stream.End().Reason)
}

func TestSseStreamMalformedFrameIsAnError(t *testing.T) {
	stream := newTestStream("event: stdout\ndata: not-json\n\n", false)

	_, err := stream.Next()
	require.ErrorContains(t, err, "malformed SSE frame (stdout)")
}

func TestSseStreamCloseRunsFinishHookOnce(t *testing.T) {
	stream := newTestStream("event: stdout\ndata: {\"output\":\"x\"}\n\n", false)
	finishes := 0
	stream.onFinish = func() { finishes++ }

	require.NoError(t, stream.Close())
	_, err := stream.Next()
	require.ErrorContains(t, err, "stream is closed")
	require.Equal(t, 1, finishes)
}

func TestStreamTerminalErrorNaturalReasonsAreNil(t *testing.T) {
	for _, reason := range []string{"exit", "removed", "eof", "final", "disconnected", sseEndClosed} {
		require.NoError(t, streamTerminalError(&SseEnd{Reason: reason}), reason)
	}
	require.ErrorContains(t, streamTerminalError(&SseEnd{Reason: "surprise"}), "unknown reason")
}

func TestIsEmptyBodySignedPathCoversStreamEndpoints(t *testing.T) {
	require.True(t, isEmptyBodySignedPath("/appmesh/app/llm-agent/task/stream"))
	require.True(t, isEmptyBodySignedPath("/appmesh/app/inference/output/stream"))
	require.True(t, isEmptyBodySignedPath("/appmesh/file/upload"))
	require.False(t, isEmptyBodySignedPath("/appmesh/app/chat/input"))
	require.False(t, isEmptyBodySignedPath("/appmesh/app/demo/task"))
}

func TestApplicationStdinSerialization(t *testing.T) {
	pipe := "pipe"
	data, err := json.Marshal(Application{Name: "chat", Stdin: &pipe})
	require.NoError(t, err)
	require.Contains(t, string(data), `"stdin":"pipe"`)

	data, err = json.Marshal(Application{Name: "chat"})
	require.NoError(t, err)
	require.NotContains(t, string(data), "stdin")
}
