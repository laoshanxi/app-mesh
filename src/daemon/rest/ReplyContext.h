// src/daemon/rest/ReplyContext.h
#ifndef REPLY_CONTEXT_H
#define REPLY_CONTEXT_H

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>

class Response;

namespace WSS
{
    // Reply context for thread-safe asynchronous responses.
    class ReplyContext
    {
    public:
        using Headers = std::map<std::string, std::string>;
        using ReplyCallback = std::function<void(std::string &&data, const std::string &status, const Headers &headers, const std::string &contentType, bool isLast, bool isBinary)>;
        // Framed covers every binary message-session transport: WSS and the TCP API.
        enum class ProtocolType { Http, Framed };

        explicit ReplyContext(ProtocolType protocolType, ReplyCallback callback, std::string connectionId = "", uint64_t numericId = 0,
                              std::string peerAddress = "", std::string principalId = "")
            : m_protocolType(protocolType), m_callback(std::move(callback)), m_connectionId(std::move(connectionId)),
              m_numericId(numericId), m_peerAddress(std::move(peerAddress)), m_principalId(std::move(principalId)) {}

        ReplyContext(const ReplyContext &) = delete;
        ReplyContext &operator=(const ReplyContext &) = delete;

        // Send HTTP response
        void replyHTTP(std::string &&httpStatus, std::string &&body, Headers &&headers, std::string &&contentType)
        {
            invokeCallback(std::move(body), httpStatus, headers, contentType, true, false);
        }

        // Send WebSocket response: the transport takes ownership of the payload.
        void replyWebSocket(std::string &&data, bool isLast = false, bool isBinary = true)
        {
            static const Headers emptyHeaders;
            invokeCallback(std::move(data), "200 OK", emptyHeaders, "text/plain", isLast, isBinary);
        }

        bool isCompleted() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_completed;
        }

        // Mark the context as aborted (e.g., client disconnected).
        // Prevents further callbacks and releases captured resources.
        void markAborted()
        {
            std::function<void()> hook;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_aborted.store(true, std::memory_order_release);
                m_completed = true;
                m_callback = nullptr;
                hook = std::move(m_abortHook);
            }
            // Outside the lock: the hook tears down the transport session.
            if (hook)
                hook();
        }

        bool isAborted() const
        {
            return m_aborted.load(std::memory_order_acquire);
        }

        ProtocolType getProtocolType() const { return m_protocolType; }
        const std::string &getConnectionId() const { return m_connectionId; }
        uint64_t getNumericId() const { return m_numericId; }
        const std::string &getPeerAddress() const { return m_peerAddress; }
        const std::string &getPrincipalId() const { return m_principalId; }

        // Optional hook invoked with the Response just before it is serialized
        // for a WebSocket reply. A transport that must inspect or amend the
        // response headers (e.g. to arm a socket file transfer) sets this when
        // the context is created; it runs on the replying worker thread.
        void setResponseObserver(std::function<void(Response &)> observer) { m_responseObserver = std::move(observer); }

        // Optional hook invoked when a request is abandoned without a reply
        // (e.g. an undecodable payload): the TCP transport closes the connection.
        void setAbortHook(std::function<void()> hook) { m_abortHook = std::move(hook); }
        void notifyResponse(Response &resp)
        {
            if (m_responseObserver)
                m_responseObserver(resp);
        }

    private:
        void invokeCallback(std::string &&data, const std::string &status, const Headers &headers, const std::string &contentType, bool isLast, bool isBinary)
        {
            ReplyCallback cb = nullptr;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (!m_completed && m_callback)
                {
                    if (isLast)
                    {
                        m_completed = true;
                        cb = std::move(m_callback); // Move out to destroy
                    }
                    else
                    {
                        cb = m_callback;
                    }
                }
            }
            if (cb) cb(std::move(data), status, headers, contentType, isLast, isBinary);
        }

        ProtocolType m_protocolType;
        ReplyCallback m_callback;
        std::string m_connectionId;
        uint64_t m_numericId{0};
        std::string m_peerAddress;
        std::string m_principalId;
        std::function<void(Response &)> m_responseObserver;
        std::function<void()> m_abortHook;
        bool m_completed{false};
        std::atomic<bool> m_aborted{false};
        mutable std::mutex m_mutex;
    };
}
#endif
