// src/daemon/rest/uwebsockets/ReplyContext.h
#ifndef REPLY_CONTEXT_H
#define REPLY_CONTEXT_H

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <map>

namespace WSS
{
    // Reply context for thread-safe asynchronous responses.
    class ReplyContext
    {
    public:
        using Headers = std::map<std::string, std::string>;
        using ReplyCallback = std::function<void(std::string &&data, const std::string &status, const Headers &headers, const std::string &contentType, bool isLast, bool isBinary)>;
        enum class ProtocolType { Http, WebSocket };

        explicit ReplyContext(ProtocolType protocolType, ReplyCallback callback)
            : m_protocolType(protocolType), m_callback(std::move(callback)) {}

        ReplyContext(const ReplyContext &) = delete;
        ReplyContext &operator=(const ReplyContext &) = delete;

        // Send HTTP response
        void replyHTTP(std::string &&httpStatus, std::string &&body, Headers &&headers, std::string &&contentType)
        {
            invokeCallback(std::move(body), httpStatus, headers, contentType, true, false);
        }

        // Send WebSocket response
        void replyData(std::string &&data, bool isLast = false, bool isBinary = true)
        {
            static const Headers emptyHeaders;
            invokeCallback(std::move(data), "200 OK", emptyHeaders, "text/plain", isLast, isBinary);
        }

        bool isCompleted() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_completed;
        }

        ProtocolType getProtocolType() const { return m_protocolType; }

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
        bool m_completed{false};
        mutable std::mutex m_mutex;
    };
}
#endif
