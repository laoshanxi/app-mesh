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
	void set_ssl_context(ACE_SSL_Context *ctx)
	{
		if (ctx)
		{
			if (this->ssl_)
				::SSL_free(this->ssl_);
			this->ssl_ = ::SSL_new(ctx->context());
			m_last_ssl_error = SSL_ERROR_NONE;
		}
	}

	int last_ssl_error() const { return m_last_ssl_error.load(); }

	ssize_t send(const void *buf, size_t len, int *out_ssl_error = nullptr)
	{
		::ERR_clear_error(); // Clear OpenSSL error queue

		ssize_t n = ACE_SSL_SOCK_Stream::send(buf, len);

		int err = SSL_ERROR_NONE;
		if (n <= 0 && this->ssl_)
		{
			err = ::SSL_get_error(this->ssl_, static_cast<int>(n));
		}

		m_last_ssl_error = err;

		if (out_ssl_error)
			*out_ssl_error = err;

		return n;
	}

	ssize_t recv(void *buf, size_t len, int *out_ssl_error = nullptr)
	{
		::ERR_clear_error(); // Clear OpenSSL error queue

		ssize_t n = ACE_SSL_SOCK_Stream::recv(buf, len);

		int err = SSL_ERROR_NONE;
		if (n <= 0 && this->ssl_)
		{
			err = ::SSL_get_error(this->ssl_, static_cast<int>(n));
		}

		m_last_ssl_error = err;

		if (out_ssl_error)
			*out_ssl_error = err;

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

	RecvResult do_recv(SSL_Stream_Ex &stream, std::uint8_t *buf, size_t len, size_t &bytes_received, int &ssl_error)
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
			LOG_DBG << "Peer closed connection during receive";
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

		LOG_ERR << "Receive operation failed with error: " << last_error_msg();
		return RecvResult::ERR;
	}

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

	bool complete() const { return (m_header_sent >= TCP_HEADER_SIZE) && (m_body_sent >= body_size()); }
	size_t body_size() const { return m_body ? m_body->size() : 0; }
	const std::unique_ptr<msgpack::sbuffer> &body() const { return m_body; }

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
			{
				LOG_DBG << "Connection closed by peer during send operation";
				return SendResult::CLOSED;
			}

			// Check SSL errors first
			if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
			{
				return SendResult::WOULD_BLOCK;
			}

			const int err = ACE_OS::last_error();
			if (err == EWOULDBLOCK || err == EAGAIN)
				return SendResult::WOULD_BLOCK;

			LOG_ERR << "Send operation failed with error: " << last_error_msg();
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
	SocketStream(ACE_SSL_Context *ctx = ACE_SSL_Context::instance(), ACE_Reactor *reactor = ACE_Reactor::instance())
		: Super(nullptr, nullptr, reactor), m_state(ConnState::CLOSED)
	{
		const static char fname[] = "SocketStream::SocketStream() ";
		LOG_DBG << fname << this;

		this->peer().set_ssl_context(ctx);
	}

	virtual ~SocketStream()
	{
		const static char fname[] = "SocketStream::~SocketStream() ";
		LOG_DBG << fname << this;
	}

	// --- Setup ---
	void onData(DataCallback cb) { m_data_cb = std::move(cb); }
	void onSent(SendCallback cb) { m_send_cb = std::move(cb); }
	void onConnect(EventCallback cb) { m_connect_cb = std::move(cb); }
	void onClose(EventCallback cb) { m_close_cb = std::move(cb); }
	void onError(ErrorCallback cb) { m_error_cb = std::move(cb); }

	// --- ACE_Acceptor Hook ---
	virtual int open(void *acceptor_or_connector = nullptr) override
	{
		ACE_UNUSED_ARG(acceptor_or_connector);
		const static char fname[] = "SocketStream::open() ";

		m_recv_state.reset();
		m_send_state.clear();
		m_ssl_want_write_for_recv.store(false, std::memory_order_relaxed);
		m_ssl_want_read_for_send.store(false, std::memory_order_relaxed);
		m_state.store(ConnState::OPEN, std::memory_order_release);

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
		this->peer().get_remote_addr(m_target);

		// Initial Registration MUST use register_handler.
		if (reactor()->register_handler(this, ACE_Event_Handler::READ_MASK) == -1)
		{
			LOG_ERR << fname << "Failed to register handler: " << last_error_msg();
			m_state.store(ConnState::CLOSED, std::memory_order_release);
			return -1;
		}

		fire_connect();
		return 0;
	}

	// ========== Client-side: Connect to remote server ==========
	bool connect(const ACE_INET_Addr &remote, const ACE_Time_Value *timeout = nullptr)
	{
		const static char fname[] = "SocketStream::connect() ";

		if (!this->reactor())
		{
			LOG_ERR << fname << "No reactor assigned";
			return false;
		}
		ACE_SSL_SOCK_Connector connector;
		// NOTE: ACE_SSL_SOCK_Connector here is blocking (consider use parent ACE_Task::svc)
		if (connector.connect(this->peer(), remote, timeout, ACE_Addr::sap_any, 1) == -1)
		{
			report_error("Connect failed");
			return false;
		}

		// For client use pair with SocketStreamPtr(ACE_Event_Handler_var)
		this->reference_counting_policy().value(ACE_Event_Handler::Reference_Counting_Policy::ENABLED);

		if (this->open(nullptr) == -1)
		{
			LOG_ERR << fname << "Failed to open socket stream after connection";
			this->peer().close();
			return false;
		}
		return true;
	}

	// --- Public API ---
	bool send(const std::string &data) { return send_impl(SendBuffer(data)); }
	bool send(const char *data, size_t len) { return send_impl(SendBuffer(data, len)); }
	bool send(std::unique_ptr<msgpack::sbuffer> &&data) { return send_impl(SendBuffer(std::move(data))); }

	// Interface function for ACE_Acceptor
	virtual int close(u_long flags = 0) { return Super::close(flags); }

	// Close from user side
	void close()
	{
		const static char fname[] = "SocketStream::close() ";

		ConnState expected = ConnState::OPEN;
		if (m_state.compare_exchange_strong(expected, ConnState::CLOSING))
		{
			LOG_DBG << fname << "Initiating graceful close for " << this;

			if (auto r = this->reactor())
			{
				if (r->notify(this, ACE_Event_Handler::EXCEPT_MASK) == -1)
				{
					LOG_WAR << fname << "Failed to notify reactor for close: " << last_error_msg();
					// Notify failed, directly trigger close
					// This is safe because we already transitioned to CLOSING
					handle_close(ACE_INVALID_HANDLE, ACE_Event_Handler::ALL_EVENTS_MASK);
				}
			}
			else
			{
				// No reactor, directly close
				std::lock_guard<std::recursive_mutex> io_lock(m_io_mutex);
				m_state.store(ConnState::CLOSED, std::memory_order_release);
				this->peer().close();
				LOG_DBG << fname << "Closed without reactor: " << this;
				fire_close();
			}
		}
	}

	bool connected() const
	{
		return m_state.load(std::memory_order_acquire) == ConnState::OPEN;
	}

	std::mutex &get_state_mutex() const { return m_cb_mutex; } // Exposed for TcpHandler::processForward

protected:
	// --- ACE_Svc_Handler Overrides ---

	virtual int handle_input(ACE_HANDLE fd = ACE_INVALID_HANDLE) override
	{
		ACE_UNUSED_ARG(fd);
		const static char fname[] = "SocketStream::handle_input() ";
		LOG_DBG << fname << this;

		std::lock_guard<std::recursive_mutex> lock(m_io_mutex);

		// 1. SSL Read Check for Send (Renegotiation)
		if (m_ssl_want_read_for_send.exchange(false))
		{
			LOG_DBG << fname << "Processing pending SSL read for send";
			handle_output(fd);
		}

		int loop_count = 0;

		while (m_state.load(std::memory_order_acquire) == ConnState::OPEN)
		{
			// Fairness: Yield to reactor
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
					report_error("Receive header error");
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
				report_error("Receive body error");
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
		const static char fname[] = "SocketStream::handle_output() ";
		LOG_DBG << fname << this;

		std::lock_guard<std::recursive_mutex> lock(m_io_mutex);

		// SSL Renegotiation Handling:
		if (m_ssl_want_write_for_recv.exchange(false))
		{
			LOG_DBG << fname << "Processing pending SSL write for receive";
			int ret = handle_input(fd);
			if (ret == -1)
				return -1;
		}

		int loop_count = 0;

		while (m_state.load(std::memory_order_acquire) == ConnState::OPEN)
		{
			// Fairness yield
			if (++loop_count > MAX_IO_LOOPS)
				return 0;

			std::shared_ptr<SendBuffer> buf = m_send_state.get_current_safe();
			if (!buf)
			{
				std::lock_guard<std::mutex> send_lock(m_send_state.mutex());
				if (m_send_state.is_empty_unsafe() && !m_ssl_want_write_for_recv.load(std::memory_order_acquire))
				{
					LOG_DBG << fname << "Send queue empty, disabling write mask";
					disable_mask(ACE_Event_Handler::WRITE_MASK);
				}
				return 0;
			}

			int ssl_err = 0;
			SendResult res = buf->do_send(this->peer(), ssl_err);
			switch (res)
			{
			case SendResult::COMPLETE:
				notify_sent(buf->body());
				continue;
			case SendResult::PROGRESS:
				continue;

			case SendResult::WOULD_BLOCK:
				if (ssl_err == SSL_ERROR_WANT_READ)
				{
					m_ssl_want_read_for_send.store(true, std::memory_order_release);
					enable_mask(ACE_Event_Handler::READ_MASK);
				}
				return 0;

			case SendResult::CLOSED:
				return -1;
			case SendResult::ERR:
				report_error("Send error");
				return -1;
			default:
				report_error("Unknown SendResult value encountered");
				return -1;
			}
		}
		return -1;
	}

	virtual int handle_exception(ACE_HANDLE) override
	{
		return -1; // Trigger close
	}

	virtual int handle_close(ACE_HANDLE h, ACE_Reactor_Mask m) override
	{
		const static char fname[] = "SocketStream::handle_close() ";

		ConnState prev = m_state.exchange(ConnState::CLOSED, std::memory_order_acq_rel);
		if (prev != ConnState::CLOSED)
		{
			std::lock_guard<std::recursive_mutex> io_lock(m_io_mutex);

			if (auto r = this->reactor())
			{
				r->remove_handler(this, ACE_Event_Handler::ALL_EVENTS_MASK | ACE_Event_Handler::DONT_CALL);
			}

			this->peer().close();
			m_send_state.clear();
			LOG_DBG << fname << this << " Socket closed and resources cleaned up";
			fire_close();
		}

		// IMPORTANT: For ACE_Acceptor mode release which not using SocketStreamPtr:
		//  - ACE_Event_Handler::Reference_Counting_Policy::DISABLED
		return Super::handle_close(h, m);
	}

private:
	bool send_impl(SendBuffer &&buf)
	{
		const static char fname[] = "SocketStream::send_impl() ";

		if (m_state.load(std::memory_order_acquire) != ConnState::OPEN)
			return false;

		{
			std::lock_guard<std::mutex> lock(m_send_state.mutex());

			// Double check state inside lock to prevent race with handle_close removal
			if (m_state.load(std::memory_order_acquire) != ConnState::OPEN)
				return false;

			m_send_state.enqueue_unsafe(std::move(buf));
			LOG_DBG << fname << "Enqueued message for sending, queue size now: " << (m_send_state.is_empty_unsafe() ? 1 : m_send_state.is_empty_unsafe());
		}

		// Check state again after releasing lock
		if (m_state.load(std::memory_order_acquire) == ConnState::OPEN)
		{
			enable_mask(ACE_Event_Handler::WRITE_MASK);
		}

		return true;
	}

	void handle_ssl_want_write(int ssl_err)
	{
		if (ssl_err == SSL_ERROR_WANT_WRITE)
		{
			m_ssl_want_write_for_recv.store(true, std::memory_order_release);
			enable_mask(ACE_Event_Handler::WRITE_MASK);
		}
	}

	int enable_mask(ACE_Reactor_Mask bit)
	{
		if (auto r = this->reactor())
			return r->mask_ops(this, bit, ACE_Reactor::ADD_MASK);
		return -1;
	}

	int disable_mask(ACE_Reactor_Mask bit)
	{
		if (auto r = this->reactor())
			return r->mask_ops(this, bit, ACE_Reactor::CLR_MASK);
		return -1;
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
		{
			try
			{
				m_close_cb();
			}
			catch (...)
			{
				LOG_ERR << "Exception thrown in close callback";
			}
		}
	}

	void deliver_message(std::vector<std::uint8_t> &&msg)
	{
		std::lock_guard<std::mutex> l(m_cb_mutex);
		if (m_data_cb)
			m_data_cb(std::move(msg));
	}

	void notify_sent(const std::unique_ptr<msgpack::sbuffer> &data)
	{
		std::lock_guard<std::mutex> l(m_cb_mutex);
		if (m_send_cb)
			m_send_cb(data);
	}

	void report_error(const std::string &msg)
	{
		LOG_ERR << "SocketStream error: " << msg << " | " << last_error_msg();
		std::lock_guard<std::mutex> l(m_cb_mutex);
		if (m_error_cb)
			m_error_cb(msg);
	}

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

class SocketStreamPtr : public ACE_Event_Handler_var
{
public:
	SocketStreamPtr() = default;
	explicit SocketStreamPtr(SocketStream *p) : ACE_Event_Handler_var(p) {}
	SocketStream *stream() { return static_cast<SocketStream *>(handler()); }
};
