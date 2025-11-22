#ifndef REPLY_CONTEXT_H
#define REPLY_CONTEXT_H

#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace WSS
{
    // Reply context for thread-safe asynchronous responses.
    class ReplyContext
    {
    public:
        using ReplyCallback = std::function<void(std::string &&data, bool isLast, bool isBinary)>;

        explicit ReplyContext(ReplyCallback callback)
            : m_callback(std::move(callback)), m_completed(false) {}

        ReplyContext(const ReplyContext &) = delete;
        ReplyContext &operator=(const ReplyContext &) = delete;

        void sendReply(std::string &&data, bool isLast = false, bool isBinary = true)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_completed && m_callback)
            {
                m_callback(std::move(data), isLast, isBinary);
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
