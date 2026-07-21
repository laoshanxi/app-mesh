// errors.go
package appmesh

import "fmt"

// APIError is returned for non-2xx daemon responses.
// Use errors.As to access its StatusCode and Message.
type APIError struct {
	StatusCode int    // HTTP status code from the daemon response
	Message    string // response body
	Op         string // operation description, e.g. "delete app"

	text string // pre-formatted message, byte-identical to the historical fmt.Errorf output
}

// Error returns the pre-formatted message for this API error.
func (e *APIError) Error() string {
	return e.text
}

// newAPIError builds an *APIError with the standard wording
// "<op> failed with status <code>: <body>".
func newAPIError(op string, statusCode int, body string) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    body,
		Op:         op,
		text:       fmt.Sprintf("%s failed with status %d: %s", op, statusCode, body),
	}
}

// newAPIErrorText builds an *APIError for call sites whose historical wording
// differs from the standard pattern; text is used verbatim as the Error() message.
func newAPIErrorText(op string, statusCode int, body string, text string) *APIError {
	return &APIError{StatusCode: statusCode, Message: body, Op: op, text: text}
}
