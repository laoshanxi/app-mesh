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
        using ReplyCallback = std::function<void(std::string &&data, const std::string &status, const std::map<std::string, std::string> &headers, const std::string &contentType, bool isLast, bool isBinary)>;

        explicit ReplyContext(ReplyCallback callback)
            : m_callback(std::move(callback)), m_completed(false) {}

        ReplyContext(const ReplyContext &) = delete;
        ReplyContext &operator=(const ReplyContext &) = delete;

        // Send HTTP response
        void replyHTTP(std::string &&httpStatus, std::string &&body, std::map<std::string, std::string> &&headers, std::string &&contentType)
        {
            bool isLast = true;
            bool isBinary = false;
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_completed && m_callback)
            {
                m_callback(std::move(body), httpStatus, headers, contentType, isLast, isBinary);
                if (isLast)
                {
                    m_completed = true;
                    m_callback = nullptr;
                }
            }
        }

        // Send WebSocket response
        void sendReply(std::string &&data, bool isLast = false, bool isBinary = true)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_completed && m_callback)
            {
                static const std::map<std::string, std::string> emptyHeaders;
                m_callback(std::move(data), "200 OK", emptyHeaders, "text/plain", isLast, isBinary);
                if (isLast)
                {
                    m_completed = true;
                    m_callback = nullptr;
                }
            }
        }

        bool isCompleted() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_completed;
        }

    private:
        ReplyCallback m_callback;
        bool m_completed;
        mutable std::mutex m_mutex; // TODO: review whether this is neccesary, m_completed can be atomic, and m_callback set null?
    };
}
#endif // REPLY_CONTEXT_H
