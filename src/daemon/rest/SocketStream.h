#pragma once

#include <ace/ACE.h>
#include <ace/INET_Addr.h>
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/Refcounted_Auto_Ptr.h>
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
#include "TcpServer.h"

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
	void set_ssl_context(ACE_SSL_Context *ctx)
	{
		if (ctx)
		{
			if (this->ssl_)
				::SSL_free(this->ssl_);
			this->ssl_ = ::SSL_new(ctx->context());
		}
	}

	int last_ssl_error() const { return m_last_ssl_error; }

	ssize_t send(const void *buf, size_t len, int *out_ssl_error = nullptr)
	{
		errno = 0; // Clear error queue for safety with non-blocking SSL
		ssize_t n = ACE_SSL_SOCK_Stream::send(buf, len);
		int ssl_err = SSL_ERROR_NONE;

		if (n <= 0 && this->ssl_)
		{
			ssl_err = ::SSL_get_error(this->ssl_, static_cast<int>(n));
			m_last_ssl_error = ssl_err;
		}
		else
		{
			m_last_ssl_error = SSL_ERROR_NONE;
		}

		if (out_ssl_error)
			*out_ssl_error = m_last_ssl_error;
		return n;
	}

	ssize_t recv(void *buf, size_t len, int *out_ssl_error = nullptr)
	{
		errno = 0;
		ssize_t n = ACE_SSL_SOCK_Stream::recv(buf, len);
		int ssl_err = SSL_ERROR_NONE;

		if (n <= 0 && this->ssl_)
		{
			ssl_err = ::SSL_get_error(this->ssl_, static_cast<int>(n));
			m_last_ssl_error = ssl_err;
		}
		else
		{
			m_last_ssl_error = SSL_ERROR_NONE;
		}

		if (out_ssl_error)
			*out_ssl_error = m_last_ssl_error;
		return n;
	}

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
	char *header_write_ptr() { return m_header_buf + m_header_offset; }

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
			LOG_ERR << fname << "Invalid magic: " << magic;
			return false;
		}

		if (len > TCP_MAX_BODY_SIZE)
		{
			LOG_ERR << fname << "Body too large: " << len;
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
	char *body_write_ptr() { return m_body_buf.data() + m_body_offset; }

	bool advance_body(size_t bytes)
	{
		m_body_offset += bytes;
		return m_body_offset >= m_expected_body_len;
	}

	std::vector<char> extract_message()
	{
		std::vector<char> result = std::move(m_body_buf);
		reset();
		return result;
	}

	// Helper to perform recv and classify the result
	RecvResult do_recv(SSL_Stream_Ex &stream, char *buf, size_t len, size_t &bytes_received, int &ssl_error)
	{
		bytes_received = 0;
		ssl_error = SSL_ERROR_NONE;

		if (len == 0)
			return RecvResult::PROGRESS; // Should not happen usually, but safe guard

		ssize_t n = stream.recv(buf, len, &ssl_error);

		if (n > 0)
		{
			bytes_received = static_cast<size_t>(n);
			return RecvResult::PROGRESS;
		}

		if (n == 0)
		{
			return RecvResult::CLOSED;
		}

		// n < 0: Check SSL error first, then errno
		if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
		{
			return RecvResult::WOULD_BLOCK;
		}

		const int err = ACE_OS::last_error();
		if (err == EWOULDBLOCK || err == EAGAIN)
		{
			return RecvResult::WOULD_BLOCK;
		}

		return RecvResult::ERR;
	}

private:
	Phase m_phase;
	char m_header_buf[TCP_HEADER_SIZE]{};
	size_t m_header_offset{};
	std::vector<char> m_body_buf;
	size_t m_body_offset{};
	size_t m_expected_body_len{};
};

// SendBuffer: One message (header + body) with progress tracking.
class SendBuffer
{
public:
	SendBuffer() = default;

	explicit SendBuffer(const char *data, size_t len)
	{
		init_header(len);
		auto sb = std::make_unique<msgpack::sbuffer>(len);
		if (len > 0)
		{
			sb->write(data, len);
		}
		m_body = std::move(sb);
	}

	explicit SendBuffer(const std::string &data)
		: SendBuffer(data.data(), data.size())
	{
	}

	explicit SendBuffer(std::unique_ptr<msgpack::sbuffer> &&data)
	{
		const size_t len = data ? data->size() : 0;
		init_header(len);
		m_body = data ? std::move(data) : std::make_unique<msgpack::sbuffer>(0);
	}

	SendBuffer(SendBuffer &&) noexcept = default;
	SendBuffer &operator=(SendBuffer &&) noexcept = default;
	SendBuffer(const SendBuffer &) = delete;
	SendBuffer &operator=(const SendBuffer &) = delete;

	bool complete() const
	{
		return (m_header_sent >= TCP_HEADER_SIZE) && (m_body_sent >= body_size());
	}

	size_t body_size() const { return m_body ? m_body->size() : 0; }

	SendResult do_send(SSL_Stream_Ex &stream, int &ssl_error)
	{
		ssl_error = SSL_ERROR_NONE;
		int ssl_err_hdr = SSL_ERROR_NONE;
		int ssl_err_body = SSL_ERROR_NONE;

		// Send header
		SendResult res = send_chunk(stream, m_header, TCP_HEADER_SIZE, m_header_sent, TCP_HEADER_SIZE, ssl_err_hdr);
		if (res != SendResult::COMPLETE)
		{
			ssl_error = ssl_err_hdr;
			return res;
		}

		// Send body
		if (body_size() > 0)
		{
			res = send_chunk(stream, m_body->data(), m_body->size(), m_body_sent, body_size(), ssl_err_body);
			ssl_error = ssl_err_body;
		}
		return res;
	}

private:
	SendResult send_chunk(SSL_Stream_Ex &stream, const char *data, size_t len, size_t &sent, size_t max_len, int &ssl_error)
	{
		ssl_error = SSL_ERROR_NONE;

		if (sent < max_len)
		{
			const char *p = data + sent;
			const size_t nleft = max_len - sent;
			ssize_t n = stream.send(p, nleft, &ssl_error);

			if (n > 0)
			{
				sent += static_cast<size_t>(n);
				if (sent >= max_len)
					return SendResult::COMPLETE;
				return SendResult::PROGRESS;
			}

			if (n == 0)
				return SendResult::CLOSED;

			// Check SSL errors first
			if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
			{
				return SendResult::WOULD_BLOCK;
			}

			const int err = ACE_OS::last_error();
			if (err == EWOULDBLOCK || err == EAGAIN)
				return SendResult::WOULD_BLOCK;

			return SendResult::ERR;
		}
		return SendResult::COMPLETE;
	}

	void init_header(size_t len)
	{
		uint32_t net_magic = host_to_net32(TCP_MAGIC);
		uint32_t net_len = host_to_net32(static_cast<uint32_t>(len));
		std::memcpy(m_header, &net_magic, 4);
		std::memcpy(m_header + 4, &net_len, 4);
		m_header_sent = 0;
		m_body_sent = 0;
	}

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
	std::shared_ptr<SendBuffer> get_current_safe()
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		if (m_current && !m_current->complete())
		{
			return m_current;
		}

		m_current.reset();

		if (!m_queue.empty())
		{
			m_current = std::make_shared<SendBuffer>(std::move(m_queue.front()));
			m_queue.pop_front();
			return m_current;
		}

		return {};
	}

	bool is_empty_unsafe() const
	{
		const bool current_done = (!m_current || m_current->complete());
		return m_queue.empty() && current_done;
	}

	void clear()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_queue.clear();
		m_current.reset();
	}

	std::mutex &mutex() { return m_mutex; }

private:
	std::mutex m_mutex;
	std::deque<SendBuffer> m_queue;
	std::shared_ptr<SendBuffer> m_current;
};

// SocketStream: Async TCP/TLS Socket
// Works with both:
//   - Server side: ACE_Acceptor<ACE_SSL_SOCK_Stream, ACE_SSL_SOCK_Acceptor>
//   - Client side: ACE_SSL_SOCK_Connector via connect() method
class SocketStream : public ACE_Svc_Handler<SSL_Stream_Ex, ACE_MT_SYNCH>
{
public:
	using Super = ACE_Svc_Handler<SSL_Stream_Ex, ACE_MT_SYNCH>;
	using DataCallback = std::function<void(std::vector<char> &&data)>;
	using EventCallback = std::function<void()>;
	using ErrorCallback = std::function<void(const std::string &err)>;

private:
	enum class ConnState : uint8_t
	{
		OPEN = 0,
		CLOSING = 1,
		CLOSED = 2
	};

	// Max loops in handle_input before yielding to reactor to prevent thread starvation
	static constexpr int MAX_IO_LOOPS = 16;

public:
	SocketStream(ACE_SSL_Context *ctx = ACE_SSL_Context::instance(), ACE_Reactor *reactor = ACE_Reactor::instance())
		: Super(nullptr, nullptr, reactor), m_state(ConnState::CLOSED)
	{
		this->peer().set_ssl_context(ctx);
		// Important: Disable standard Svc_Handler destruction to support Refcounted_Auto_Ptr
		this->reference_counting_policy().value(ACE_Event_Handler::Reference_Counting_Policy::ENABLED);
	}

	virtual ~SocketStream()
	{
		if (m_state.load(std::memory_order_acquire) != ConnState::CLOSED)
		{
			close_internal(false);
		}
	}

	virtual void destroy() override
	{
		this->remove_reference();
	}

	// --- Setup ---
	void onData(DataCallback cb) { m_data_cb = std::move(cb); }
	void onConnect(EventCallback cb) { m_connect_cb = std::move(cb); }
	void onClose(EventCallback cb) { m_close_cb = std::move(cb); }
	void onError(ErrorCallback cb) { m_error_cb = std::move(cb); }

	// --- ACE_Acceptor Hook ---
	virtual int open(void *acceptor_or_connector = nullptr) override
	{
		ACE_UNUSED_ARG(acceptor_or_connector);
		const static char fname[] = "SocketStream::open() ";
		m_state.store(ConnState::OPEN, std::memory_order_release);
		m_recv_state.reset();
		m_send_state.clear();

		int nodelay = 1;
		if (this->peer().set_option(ACE_IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) == -1)
		{
			LOG_ERR << fname << "Can't disable Nagle's algorithm: " << last_error_msg();
		}
		// Enable non-blocking mode
		if (this->peer().enable(ACE_NONBLOCK) == -1)
		{
			LOG_ERR << fname << "Failed to enable non-blocking mode: " << last_error_msg();
		}

		// Cache mask: Start with NULL
		m_cached_mask.store(ACE_Event_Handler::NULL_MASK, std::memory_order_release);

		this->add_reference();

		// Initial Registration MUST use register_handler.
		if (reactor()->register_handler(this, ACE_Event_Handler::READ_MASK) == -1)
		{
			this->remove_reference();
			return -1;
		}

		// Update cache after successful registration
		update_cached_mask(ACE_Event_Handler::READ_MASK, true);

		fire_connect();
		return 0;
	}

	// ========== Client-side: Connect to remote server ==========
	bool connect(const ACE_INET_Addr &remote, const ACE_Time_Value *timeout = nullptr)
	{
		if (!this->reactor())
			return false;

		// Note: This connect call is synchronous/blocking for SSL handshake unless strictly managed.
		// For true async connect, ACE_Connector with ACE_Synch_Options is needed, but that complicates lifecycle.
		// Keeping this simple as per request, but be aware it blocks the calling thread.
		ACE_SSL_SOCK_Connector connector;
		if (connector.connect(this->peer(), remote, timeout, ACE_Addr::sap_any, 1) == -1)
		{
			report_error("Connect failed");
			return false;
		}
		return (this->open(nullptr) == 0);
	}

	// --- Public API ---
	void send(const std::string &data) { send_impl(SendBuffer(data)); }
	void send(const char *data, size_t len) { send_impl(SendBuffer(data, len)); }
	void send(std::unique_ptr<msgpack::sbuffer> &&data) { send_impl(SendBuffer(std::move(data))); }

	void close()
	{
		ConnState expected = ConnState::OPEN;
		if (m_state.compare_exchange_strong(expected, ConnState::CLOSING))
		{
			// Notify reactor to handle close in its thread
			if (auto r = this->reactor())
				r->notify(this, ACE_Event_Handler::EXCEPT_MASK);
		}
	}

	bool connected() const
	{
		return (m_state.load(std::memory_order_acquire) == ConnState::OPEN) && (this->peer().get_handle() != ACE_INVALID_HANDLE);
	}

	std::mutex &get_state_mutex() const { return m_cb_mutex; } // Exposed for TcpHandler::processForward

	// --- ACE_Svc_Handler Overrides ---

	virtual int handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE) override
	{
		ACE_UNUSED_ARG(fd);
		// RECURSIVE lock: Allows handle_output to call us during SSL renegotiation
		std::lock_guard<std::recursive_mutex> lock(m_io_mutex);

		// 1. SSL Write Check: If SSL wanted write during recv, and we are here,
		// we might be here because of a WRITE event that we redirected to handle_input
		// via the m_ssl_want_write_for_recv flag logic, or normal READ.
		// If we were blocked on write for recv, we can try receiving again.

		// 2. SSL Read Check for Send: If Send was blocked on READ, notify send logic.
		if (m_ssl_want_read_for_send)
		{
			m_ssl_want_read_for_send = false;
			// Trigger output processing.
			handle_output(fd);
		}

		int loop_count = 0;

		while (m_state.load(std::memory_order_acquire) == ConnState::OPEN)
		{
			// Fairness: Yield to reactor after N loops to prevent this thread from being hogged
			if (++loop_count > MAX_IO_LOOPS)
				return 0;

			// Process Header
			if (m_recv_state.phase() == RecvState::READING_HEADER)
			{
				size_t received = 0;
				int ssl_err = 0;
				RecvResult res = m_recv_state.do_recv(this->peer(), m_recv_state.header_write_ptr(), m_recv_state.header_bytes_needed(), received, ssl_err);

				if (res == RecvResult::PROGRESS)
				{
					if (m_recv_state.advance_header(received))
					{
						if (!m_recv_state.parse_header())
							return -1; // Protocol error
						if (m_recv_state.expected_body_len() == 0)
							deliver_message(m_recv_state.extract_message());
					}
					continue;
				}
				if (res == RecvResult::CLOSED)
					return -1;
				if (res == RecvResult::ERR)
				{
					report_error("Recv header error");
					return -1;
				}
				if (res == RecvResult::WOULD_BLOCK)
				{
					handle_ssl_want_write(ssl_err);
					return 0;
				}
			}

			// Process Body
			size_t received = 0;
			int ssl_err = 0;
			RecvResult res = m_recv_state.do_recv(this->peer(), m_recv_state.body_write_ptr(), m_recv_state.body_bytes_needed(), received, ssl_err);

			if (res == RecvResult::PROGRESS)
			{
				if (m_recv_state.advance_body(received))
					deliver_message(m_recv_state.extract_message());
				continue;
			}
			if (res == RecvResult::CLOSED)
				return -1;
			if (res == RecvResult::ERR)
			{
				report_error("Recv body error");
				return -1;
			}
			if (res == RecvResult::WOULD_BLOCK)
			{
				handle_ssl_want_write(ssl_err);
				return 0;
			}
		}
		return -1;
	}

	virtual int handle_output(ACE_HANDLE fd = ACE_INVALID_HANDLE) override
	{
		ACE_UNUSED_ARG(fd);
		std::lock_guard<std::recursive_mutex> lock(m_io_mutex);

		// SSL Renegotiation Handling:
		// If we enabled WRITE mask because recv() returned SSL_ERROR_WANT_WRITE,
		// we must try to drive the recv state machine now that we can write.
		if (m_ssl_want_write_for_recv)
		{
			m_ssl_want_write_for_recv = false;
			// Drive the input handler.
			int ret = handle_input(fd);
			if (ret == -1)
				return -1;
			// After driving input, if we still have send data, continue.
			// Otherwise, return 0 to keep reactor happy.
		}

		while (m_state.load(std::memory_order_acquire) == ConnState::OPEN)
		{
			// We must hold the send state mutex to check empty AND clear mask
			// to prevent the race where someone adds data and sets mask between our check and clear.
			std::shared_ptr<SendBuffer> buf;
			{
				std::lock_guard<std::mutex> send_lock(m_send_state.mutex());

				// Try to get cached current or pop new one
				// We peek first because if it's empty we need to clear mask inside lock
				if (m_send_state.is_empty_unsafe())
				{
					// Queue empty.
					// CRITICAL ATOMICITY: Clear WRITE mask inside the lock to ensure we don't
					// race with send_impl adding data.
					if (!m_ssl_want_write_for_recv)
					{
						disable_mask(ACE_Event_Handler::WRITE_MASK);
					}
					return 0;
				}
			}

			// Retrieve next buffer (internal lock used inside, but safe)
			buf = m_send_state.get_current_safe();
			if (!buf)
				continue; // Should not happen given check above, but safety first

			int ssl_err = 0;
			SendResult res = buf->do_send(this->peer(), ssl_err);

			if (res == SendResult::PROGRESS || res == SendResult::COMPLETE)
				continue;
			if (res == SendResult::CLOSED)
				return -1;
			if (res == SendResult::ERR)
			{
				report_error("Send error");
				return -1;
			}

			if (res == SendResult::WOULD_BLOCK)
			{
				if (ssl_err == SSL_ERROR_WANT_READ)
				{
					// SSL needs to read to complete the write (renegotiation)
					m_ssl_want_read_for_send = true;
					// Enable READ mask safely
					enable_mask(ACE_Event_Handler::READ_MASK);
					// Keep WRITE mask enabled so we come back here when needed?
					// Usually WANT_READ means we wait for Read.
					// We do NOT clear Write mask because we haven't finished the write logic.
				}
				return 0;
			}
		}
		return -1;
	}

	virtual int handle_exception(ACE_HANDLE) override
	{
		return -1; // Trigger close
	}

	virtual int handle_close(ACE_HANDLE, ACE_Reactor_Mask) override
	{
		// This is called by Reactor when handle_input/output/exception returns -1
		close_internal(true);
		return 0;
	}

private:
	void send_impl(SendBuffer &&buf)
	{
		if (m_state.load(std::memory_order_acquire) != ConnState::OPEN)
			return;

		{
			std::lock_guard<std::mutex> lock(m_send_state.mutex());
			m_send_state.enqueue_unsafe(std::move(buf));

			// CRITICAL ATOMICITY: Enable WRITE mask INSIDE the lock.
			// This prevents the "stalled send" bug where handle_output clears the mask
			// *after* we queued data but *before* we enabled the mask.
			enable_mask(ACE_Event_Handler::WRITE_MASK);
		}

		// NOTE: No notify() needed. mask_ops() is sufficient for Reactor to wake up.
	}

	void handle_ssl_want_write(int ssl_err)
	{
		if (ssl_err == SSL_ERROR_WANT_WRITE)
		{
			m_ssl_want_write_for_recv = true;
			enable_mask(ACE_Event_Handler::WRITE_MASK);
		}
	}

	// Helper to add mask safely (Thread Safe)
	int enable_mask(ACE_Reactor_Mask bit)
	{
		ACE_Reactor_Mask old = m_cached_mask.load(std::memory_order_relaxed);
		if ((old & bit) == bit)
			return 0; // Already set

		if (reactor()->mask_ops(this, bit, ACE_Reactor::ADD_MASK) == -1)
			return -1;

		update_cached_mask(bit, true);
		return 0;
	}

	// Helper to remove mask safely (Thread Safe)
	int disable_mask(ACE_Reactor_Mask bit)
	{
		ACE_Reactor_Mask old = m_cached_mask.load(std::memory_order_relaxed);
		if ((old & bit) == 0)
			return 0;

		if (reactor()->mask_ops(this, bit, ACE_Reactor::CLR_MASK) == -1)
			return -1;

		update_cached_mask(bit, false);
		return 0;
	}

	void update_cached_mask(ACE_Reactor_Mask bit, bool set)
	{
		if (set)
			m_cached_mask.fetch_or(bit, std::memory_order_release);
		else
			m_cached_mask.fetch_and(~bit, std::memory_order_release);
	}

	void close_internal(bool from_reactor)
	{
		ConnState prev = m_state.exchange(ConnState::CLOSED, std::memory_order_acq_rel);
		if (prev == ConnState::CLOSED)
			return;

		if (!from_reactor && this->reactor())
		{
			// Use DONT_CALL to prevent recursive handle_close
			this->reactor()->remove_handler(this, ACE_Event_Handler::ALL_EVENTS_MASK | ACE_Event_Handler::DONT_CALL);
		}

		this->peer().close();
		fire_close();
		this->destroy(); // Decrements ref count, pair with add_reference in open()
	}

	void fire_connect()
	{
		std::lock_guard<std::mutex> l(m_cb_mutex);
		if (m_connect_cb)
			m_connect_cb();
	}

	void fire_close()
	{
		std::lock_guard<std::mutex> l(m_cb_mutex);
		if (m_close_cb)
			m_close_cb();
	}

	void deliver_message(std::vector<char> &&msg)
	{
		std::lock_guard<std::mutex> l(m_cb_mutex);
		if (m_data_cb)
			m_data_cb(std::move(msg));
	}

	void report_error(const std::string &msg)
	{
		LOG_ERR << "SocketStream: " << msg << " (" << last_error_msg() << ")";
		std::lock_guard<std::mutex> l(m_cb_mutex);
		if (m_error_cb)
			m_error_cb(msg);
	}

private:
	std::atomic<ConnState> m_state;

	RecvState m_recv_state;
	SendState m_send_state;

	bool m_ssl_want_write_for_recv{false};
	bool m_ssl_want_read_for_send{false};

	mutable std::recursive_mutex m_io_mutex;	 // Recursive for SSL renegotiation
	mutable std::mutex m_cb_mutex;				 // Protects callbacks
	std::atomic<ACE_Reactor_Mask> m_cached_mask; // Simple cache to avoid redundant calls

	DataCallback m_data_cb;
	EventCallback m_connect_cb;
	EventCallback m_close_cb;
	ErrorCallback m_error_cb;
};

using TcpStreamPtr = ACE_Refcounted_Auto_Ptr<SocketStream, ACE_Thread_Mutex>;
