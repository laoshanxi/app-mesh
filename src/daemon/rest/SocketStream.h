// src/daemon/rest/SocketStream.h
#pragma once

#include <ace/ACE.h>
#include <ace/Event_Handler_T.h>
#include <ace/INET_Addr.h>
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/Svc_Handler.h>
#include <ace/TP_Reactor.h>
#include <ace/os_include/netinet/os_tcp.h>
#include <msgpack.hpp>

#ifdef __has_include
#if __has_include(<ace/SSL/SSL_SOCK_Connector.h>)
#include <ace/SSL/SSL_Context.h>
#include <ace/SSL/SSL_SOCK_Connector.h>
#include <ace/SSL/SSL_SOCK_Stream.h>
#else
#include <ace/SSL_Context.h>
#include <ace/SSL_SOCK_Connector.h>
#include <ace/SSL_SOCK_Stream.h>
#endif
#else
#include <ace/SSL/SSL_Context.h>
#include <ace/SSL/SSL_SOCK_Connector.h>
#include <ace/SSL/SSL_SOCK_Stream.h>
#endif

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "../../common/Utility.h"

// Protocol constants
static constexpr size_t TCP_HEADER_SIZE = TCP_MESSAGE_HEADER_LENGTH;
static constexpr uint32_t TCP_MAGIC = TCP_MESSAGE_MAGIC;
static constexpr size_t TCP_MAX_BODY_SIZE = TCP_MAX_BLOCK_SIZE;

// Network byte order helpers
inline uint32_t host_to_net32(uint32_t x) { return ACE_HTONL(x); }
inline uint32_t net_to_host32(uint32_t x) { return ACE_NTOHL(x); }

// SSL_Stream_Ex: ACE_SSL_SOCK_Stream with customized ACE_SSL_Context
class SSL_Stream_Ex : public ACE_SSL_SOCK_Stream
{
public:
	void set_ssl_context(ACE_SSL_Context *ctx);
	int last_ssl_error() const { return m_last_ssl_error.load(); }

	ssize_t send(const void *buf, size_t len, int *out_ssl_error = nullptr);
	ssize_t recv(void *buf, size_t len, int *out_ssl_error = nullptr);

private:
	mutable std::atomic<int> m_last_ssl_error{SSL_ERROR_NONE};
};

// SendResult: Distinguishes between different send outcomes
enum class SendResult
{
	PROGRESS,	 // Bytes were sent, more to send
	COMPLETE,	 // Buffer fully sent
	WOULD_BLOCK, // Would block, try again later
	CLOSED,		 // Peer closed connection
	ERR			 // Fatal error occurred
};

// RecvResult: Distinguishes between different recv outcomes
enum class RecvResult
{
	PROGRESS,	 // Bytes were received
	WOULD_BLOCK, // Would block, try again later
	CLOSED,		 // Peer closed connection
	ERR			 // Fatal error occurred
};

// RecvState: Manages receive buffer state for one connection
class RecvState
{
public:
	enum Phase
	{
		READING_HEADER,
		READING_BODY
	};

	RecvState() { reset(); }

	void reset()
	{
		m_phase = READING_HEADER;
		m_header_offset = 0;
		m_body_offset = 0;
		m_expected_body_len = 0;
		m_body_buf.clear();
	}

	Phase phase() const { return m_phase; }

	size_t header_bytes_needed() const { return TCP_HEADER_SIZE - m_header_offset; }
	std::uint8_t *header_write_ptr() { return m_header_buf + m_header_offset; }

	bool advance_header(size_t bytes)
	{
		m_header_offset += bytes;
		return m_header_offset >= TCP_HEADER_SIZE;
	}

	bool parse_header()
	{
		const static char fname[] = "RecvState::parse_header() ";

		uint32_t net_magic = 0, net_len = 0;
		std::memcpy(&net_magic, m_header_buf, 4);
		std::memcpy(&net_len, m_header_buf + 4, 4);

		uint32_t magic = net_to_host32(net_magic);
		uint32_t len = net_to_host32(net_len);

		if (magic != TCP_MAGIC)
		{
			LOG_ERR << fname << "Invalid magic number: 0x" << std::hex;
			return false;
		}

		if (len > TCP_MAX_BODY_SIZE)
		{
			LOG_ERR << fname << "Message body too large: " << len << ", maximum allowed: " << TCP_MAX_BODY_SIZE;
			return false;
		}

		m_expected_body_len = static_cast<size_t>(len);
		m_body_buf.resize(m_expected_body_len); // TODO: catch exception
		m_body_offset = 0;
		m_phase = READING_BODY;
		return true;
	}

	size_t expected_body_len() const { return m_expected_body_len; }
	size_t body_bytes_needed() const { return m_expected_body_len - m_body_offset; }
	std::uint8_t *body_write_ptr() { return m_body_buf.data() + m_body_offset; }

	bool advance_body(size_t bytes)
	{
		m_body_offset += bytes;
		return m_body_offset >= m_expected_body_len;
	}

	std::vector<std::uint8_t> extract_message()
	{
		std::vector<std::uint8_t> result = std::move(m_body_buf);
		reset();
		return result;
	}

	RecvResult do_recv(SSL_Stream_Ex &stream, std::uint8_t *buf, size_t len, size_t &bytes_received, int &ssl_error);

private:
	Phase m_phase;
	std::uint8_t m_header_buf[TCP_HEADER_SIZE]{};
	size_t m_header_offset{};
	std::vector<std::uint8_t> m_body_buf;
	size_t m_body_offset{};
	size_t m_expected_body_len{};
};

// SendBuffer: One message (header + body) with progress tracking.
class SendBuffer
{
public:
	explicit SendBuffer(std::unique_ptr<msgpack::sbuffer> &&data);
	explicit SendBuffer(const char *data, size_t len);
	explicit SendBuffer(const std::string &data) : SendBuffer(data.data(), data.size()) {}

	SendBuffer(SendBuffer &&) noexcept = default;
	SendBuffer &operator=(SendBuffer &&) noexcept = default;
	SendBuffer(const SendBuffer &) = delete;
	SendBuffer &operator=(const SendBuffer &) = delete;

	bool complete() const { return (m_header_sent >= TCP_HEADER_SIZE) && (m_body_sent >= body_size()); }
	size_t body_size() const { return m_body ? m_body->size() : 0; }
	const std::unique_ptr<msgpack::sbuffer> &body() const { return m_body; }

	SendResult do_send(SSL_Stream_Ex &stream, int &ssl_error);

private:
	SendResult send_chunk(SSL_Stream_Ex &stream, const char *data, size_t len, size_t &sent, size_t max_len, int &ssl_error);
	void init_header(size_t len);

private:
	char m_header[TCP_HEADER_SIZE]{}; // 8-byte header: 4 bytes magic, 4 bytes length
	size_t m_header_sent{0};
	std::unique_ptr<msgpack::sbuffer> m_body;
	size_t m_body_sent{0};
};

// SendState: Manages send queue for one connection (thread-safe)
class SendState
{
public:
	// Called from any thread
	void enqueue_unsafe(SendBuffer &&buf)
	{
		m_queue.push_back(std::move(buf));
	}

	// Called from reactor thread
	std::shared_ptr<SendBuffer> get_current_safe();

	bool is_empty_unsafe() const
	{
		const bool current_done = (!m_current || m_current->complete());
		return m_queue.empty() && current_done;
	}

	void clear();

	std::mutex &mutex() { return m_mutex; }

private:
	std::mutex m_mutex;
	std::deque<SendBuffer> m_queue;
	std::shared_ptr<SendBuffer> m_current;
};

class SocketStreamPtr;

// SocketStream: Async TCP/TLS Socket
// Works with both:
//   - Server side: ACE_Acceptor<ACE_SSL_SOCK_Stream, ACE_SSL_SOCK_Acceptor>
//   - Client side: ACE_SSL_SOCK_Connector via connect() method
class SocketStream : public ACE_Svc_Handler<SSL_Stream_Ex, ACE_MT_SYNCH>
{
public:
	using Super = ACE_Svc_Handler<SSL_Stream_Ex, ACE_MT_SYNCH>;
	using DataCallback = std::function<void(std::vector<std::uint8_t> &&data)>;
	using SendCallback = std::function<void(const std::unique_ptr<msgpack::sbuffer> &data)>;
	using EventCallback = std::function<void()>;
	using ErrorCallback = std::function<void(const std::string &err)>;

private:
	enum class ConnState : uint8_t
	{
		OPEN = 0,
		CLOSING = 1,
		CLOSED = 2
	};
	static constexpr int MAX_IO_LOOPS = 16;

public:
	SocketStream(ACE_SSL_Context *ctx = ACE_SSL_Context::instance(), ACE_Reactor *reactor = ACE_Reactor::instance());
	virtual ~SocketStream();

	// --- Setup ---
	void onData(DataCallback cb) { m_data_cb = std::move(cb); }
	void onSent(SendCallback cb) { m_send_cb = std::move(cb); }
	void onConnect(EventCallback cb) { m_connect_cb = std::move(cb); }
	void onClose(EventCallback cb) { m_close_cb = std::move(cb); }
	void onError(ErrorCallback cb) { m_error_cb = std::move(cb); }

	// --- ACE_Acceptor Hook ---
	virtual int open(void *acceptor_or_connector = nullptr) override;

	// ========== Client-side: Connect to remote server ==========
	bool connect(const ACE_INET_Addr &remote, const ACE_Time_Value *timeout = nullptr);

	/// Create a new client SocketStream and connect to the remote address.
	/// Always returns a valid SocketStreamPtr; check connected() for success.
	static SocketStreamPtr createConnection(const ACE_INET_Addr &remote, const ACE_Time_Value *timeout = nullptr);

	// --- Public API ---
	bool send(const std::string &data);
	bool send(const char *data, size_t len);
	bool send(std::unique_ptr<msgpack::sbuffer> &&data);

	// Close from user side (close function is already used for interface)
	void shutdown();
	bool connected() const;

	std::mutex &get_state_mutex() const; // Exposed for Worker::forward

protected:
	// --- ACE_Svc_Handler Overrides ---
	virtual int handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE) override;
	virtual int handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE) override;
	virtual int handle_exception(ACE_HANDLE) override;
	virtual int handle_close(ACE_HANDLE h, ACE_Reactor_Mask m) override;

private:
	bool send_impl(SendBuffer &&buf);
	void handle_ssl_want_write(int ssl_err);

	int enable_mask(ACE_Reactor_Mask bit);
	int disable_mask(ACE_Reactor_Mask bit);

	void fire_connect();
	void fire_close();
	void deliver_message(std::vector<std::uint8_t> &&msg);
	void notify_sent(const std::unique_ptr<msgpack::sbuffer> &data);
	void report_error(const std::string &msg);

private:
	ACE_INET_Addr m_target;
	std::atomic<ConnState> m_state;

	RecvState m_recv_state;
	SendState m_send_state;

	std::atomic<bool> m_ssl_want_write_for_recv{false};
	std::atomic<bool> m_ssl_want_read_for_send{false};

	mutable std::recursive_mutex m_io_mutex; // Recursive for SSL renegotiation
	mutable std::mutex m_cb_mutex;			 // Protects callbacks

	DataCallback m_data_cb;
	SendCallback m_send_cb;
	EventCallback m_connect_cb;
	EventCallback m_close_cb;
	ErrorCallback m_error_cb;
};

class SocketStreamPtr
{
public:
	SocketStreamPtr() = default;

	/// @brief Wraps a raw pointer with optional reference increment.
	/// @param p The SocketStream instance to manage.
	///  Note: A new ACE_Event_Handler typically starts with a ref_count of 1.
	///  Since we already clear the construction reference in SocketStream::open, so always use add_ref=true here to avoid premature deletion.
	/// @param add_ref Control logic:
	///  - true (Guard Mode): Use for existing objects to prevent deletion.
	///  - false (Transfer Mode): Use for 'new' objects to take ownership.
	explicit SocketStreamPtr(SocketStream *p, bool add_ref = true) : m_var(p)
	{
		if (m_var.handler() && add_ref)
		{
			m_var.handler()->add_reference();
		}
	}

	SocketStreamPtr(const SocketStreamPtr &) = default;
	SocketStreamPtr &operator=(const SocketStreamPtr &) = default;

	SocketStream *stream() const { return static_cast<SocketStream *>(m_var.handler()); }
	SocketStream *operator->() const { return stream(); }
	SocketStream &operator*() const { return *stream(); }
	explicit operator bool() const { return m_var.handler() != nullptr; }
	void reset() { m_var = nullptr; }

private:
	ACE_Event_Handler_var m_var;
};
