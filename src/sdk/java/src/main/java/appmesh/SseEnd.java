package appmesh;

/**
 * Terminal marker of an SSE stream, filled from the daemon's closing {@code end} event.
 * Every stream emits exactly one; {@code reason} is {@code exit | removed | timeout | eof |
 * final | disconnected | error}, or {@code closed} when the peer cut the stream without one.
 */
public class SseEnd {
    private final String reason;
    private final Integer exitCode;
    private final Long position;
    private final Integer status;
    private final String message;
    private final String result;

    SseEnd(String reason, Integer exitCode, Long position, Integer status, String message, String result) {
        this.reason = reason;
        this.exitCode = exitCode;
        this.position = position;
        this.status = status;
        this.message = message;
        this.result = result;
    }

    /** Why the stream ended: exit | removed | timeout | eof | final | disconnected | error | closed. */
    public String getReason() {
        return reason;
    }

    /** Output streams: process exit code when the reason is {@code exit}. */
    public Integer getExitCode() {
        return exitCode;
    }

    /** Output streams: final stdout byte cursor. */
    public Long getPosition() {
        return position;
    }

    /** Task streams: HTTP status carried by an {@code error} end event. */
    public Integer getStatus() {
        return status;
    }

    /** Task streams: error message. */
    public String getMessage() {
        return message;
    }

    /** Task streams: the final result payload (the same string {@code runTask} would return). */
    public String getResult() {
        return result;
    }

    @Override
    public String toString() {
        return "SseEnd[reason=" + reason + ", exitCode=" + exitCode + ", position=" + position
                + ", status=" + status + ", message=" + message + ", result=" + result + "]";
    }
}
