// src/daemon/rest/SocketStream.cpp
#include "SocketStream.h"

// SSL_Stream_Ex methods
void SSL_Stream_Ex::set_ssl_context(ACE_SSL_Context *ctx)
{
	if (ctx)
	{
		if (this->ssl_)
			::SSL_free(this->ssl_);
		this->ssl_ = ::SSL_new(ctx->context());
		m_last_ssl_error = SSL_ERROR_NONE;
	}
}

ssize_t SSL_Stream_Ex::send(const void *buf, size_t len, int *out_ssl_error)
{
	// Clear OpenSSL error queue
	::ERR_clear_error();
	ssize_t n = ACE_SSL_SOCK_Stream::send(buf, len);

	// Assume SUCCESS/NONE initially
	int err = SSL_ERROR_NONE;

	// Only query SSL_get_error if n <= 0.
	// If n > 0, SSL_get_error is undefined/irrelevant for data operations.
	if (n <= 0)
	{
		if (this->ssl())
			err = ::SSL_get_error(this->ssl(), static_cast<int>(n));
		else
			err = SSL_ERROR_SYSCALL; // Fallback if SSL object is missing
	}

	m_last_ssl_error = err;
	if (out_ssl_error)
		*out_ssl_error = err;

	return n;
}

ssize_t SSL_Stream_Ex::recv(void *buf, size_t len, int *out_ssl_error)
{
	// Clear OpenSSL error queue
	::ERR_clear_error();

	ssize_t n = ACE_SSL_SOCK_Stream::recv(buf, len);
	int err = SSL_ERROR_NONE;
	if (n <= 0)
	{
		if (this->ssl())
			err = ::SSL_get_error(this->ssl(), static_cast<int>(n));
		else
			err = SSL_ERROR_SYSCALL;
	}

	m_last_ssl_error = err;
	if (out_ssl_error)
		*out_ssl_error = err;

	return n;
}

// RecvState methods
RecvResult RecvState::do_recv(SSL_Stream_Ex &stream, std::uint8_t *buf, size_t len, size_t &bytes_received, int &ssl_error)
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

	// n <= 0 → SSL semantics apply
	switch (ssl_error)
	{
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		return RecvResult::WOULD_BLOCK;

	case SSL_ERROR_ZERO_RETURN:
		// Clean shutdown (close_notify received)
		LOG_DBG << "Peer closed connection cleanly";
		return RecvResult::CLOSED;

	case SSL_ERROR_SYSCALL:
	{
		if (n == 0)
		{
			// EOF violation (peer closed socket without sending close_notify)
			LOG_DBG << "Peer closed connection unexpectedly (EOF)";
			return RecvResult::CLOSED;
		}

		const int err = ACE_OS::last_error();
		if (err == EWOULDBLOCK || err == EAGAIN)
			return RecvResult::WOULD_BLOCK;

		LOG_ERR << "Receive syscall failed: " << last_error_msg();
		return RecvResult::ERR;
	}

	default:
		LOG_ERR << "SSL Recv error code: " << ssl_error;
		return RecvResult::ERR;
	}
}

// SendBuffer methods
SendBuffer::SendBuffer(const char *data, size_t len)
{
	init_header(len);
	auto sb = std::make_unique<msgpack::sbuffer>(len);
	if (len > 0)
	{
		sb->write(data, len);
	}
	m_body = std::move(sb);
}

SendBuffer::SendBuffer(std::unique_ptr<msgpack::sbuffer> &&data)
{
	const size_t len = data ? data->size() : 0;
	init_header(len);
	m_body = data ? std::move(data) : std::make_unique<msgpack::sbuffer>(0);
}

SendResult SendBuffer::do_send(SSL_Stream_Ex &stream, int &ssl_error)
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

SendResult SendBuffer::send_chunk(SSL_Stream_Ex &stream, const char *data, size_t len, size_t &sent, size_t max_len, int &ssl_error)
{
	// Reset error state before operation
	ssl_error = SSL_ERROR_NONE;

	if (sent >= max_len)
		return SendResult::COMPLETE;

	const char *p = data + sent;
	const size_t nleft = max_len - sent;

	ssize_t n = stream.send(p, nleft, &ssl_error);

	if (n > 0)
	{
		sent += static_cast<size_t>(n);
		return (sent >= max_len) ? SendResult::COMPLETE : SendResult::PROGRESS;
	}

	// Handle n <= 0 via SSL_get_error result
	switch (ssl_error)
	{
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		return SendResult::WOULD_BLOCK;

	case SSL_ERROR_ZERO_RETURN:
		// The peer has sent a "close notify" alert cleanly
		LOG_DBG << "Connection closed by peer (SSL_ERROR_ZERO_RETURN)";
		return SendResult::CLOSED;

	case SSL_ERROR_SYSCALL:
	{
		// Underlying I/O error. Check errno.
		// Note: If n == 0 here, it often means EOF from peer without close_notify.
		if (n == 0)
		{
			LOG_DBG << "Connection closed unexpectedly (EOF)";
			return SendResult::CLOSED;
		}

		const int err = ACE_OS::last_error();
		if (err == EWOULDBLOCK || err == EAGAIN)
			return SendResult::WOULD_BLOCK;

		LOG_ERR << "Send syscall failed: " << last_error_msg();
		return SendResult::ERR;
	}

	default:
		// SSL_ERROR_SSL and others
		LOG_ERR << "SSL Send error code: " << ssl_error;
		return SendResult::ERR;
	}
}

void SendBuffer::init_header(size_t len)
{
	uint32_t net_magic = host_to_net32(TCP_MAGIC);
	uint32_t net_len = host_to_net32(static_cast<uint32_t>(len));
	std::memcpy(m_header, &net_magic, 4);
	std::memcpy(m_header + 4, &net_len, 4);
	m_header_sent = 0;
	m_body_sent = 0;
}

// SendState methods
std::shared_ptr<SendBuffer> SendState::get_current_safe()
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

void SendState::clear()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_queue.clear();
	m_current.reset();
}

// SocketStream methods
SocketStream::SocketStream(ACE_SSL_Context *ctx, ACE_Reactor *reactor)
	: Super(nullptr, nullptr, reactor), m_state(ConnState::CLOSED)
{
	const static char fname[] = "SocketStream::SocketStream() ";
	LOG_DBG << fname << this;

	// Both ACE_Acceptor and ACE_Connector modes use reference counting (SocketStreamPtr).
	this->reference_counting_policy().value(ACE_Event_Handler::Reference_Counting_Policy::ENABLED);

	this->peer().set_ssl_context(ctx);
}

SocketStream::~SocketStream()
{
	const static char fname[] = "SocketStream::~SocketStream() ";
	LOG_DBG << fname << this;
}

int SocketStream::open(void *acceptor_or_connector)
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

		this->remove_reference(); // Release the construction reference
		return -1;
	}

	fire_connect();
	this->remove_reference(); // Release the construction reference
	return 0;
}

bool SocketStream::connect(const ACE_INET_Addr &remote, const ACE_Time_Value *timeout)
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

	if (this->open(nullptr) == -1)
	{
		LOG_ERR << fname << "Failed to open socket stream after connection";
		this->peer().close();
		return false;
	}
	return true;
}

bool SocketStream::send(const std::string &data) { return send_impl(SendBuffer(data)); }
bool SocketStream::send(const char *data, size_t len) { return send_impl(SendBuffer(data, len)); }
bool SocketStream::send(std::unique_ptr<msgpack::sbuffer> &&data) { return send_impl(SendBuffer(std::move(data))); }

void SocketStream::shutdown()
{
	const static char fname[] = "SocketStream::shutdown() ";

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

bool SocketStream::connected() const
{
	return m_state.load(std::memory_order_acquire) == ConnState::OPEN;
}

std::mutex &SocketStream::get_state_mutex() const { return m_cb_mutex; }

int SocketStream::handle_input(ACE_HANDLE fd)
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

int SocketStream::handle_output(ACE_HANDLE fd)
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

int SocketStream::handle_exception(ACE_HANDLE)
{
	return -1; // Trigger close
}

int SocketStream::handle_close(ACE_HANDLE h, ACE_Reactor_Mask m)
{
	const static char fname[] = "SocketStream::handle_close() ";
	LOG_DBG << fname << this;

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

	return Super::handle_close(h, m); // Important for ACE_Event_Handler::Reference_Counting_Policy::DISABLED
}

bool SocketStream::send_impl(SendBuffer &&buf)
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

void SocketStream::handle_ssl_want_write(int ssl_err)
{
	if (ssl_err == SSL_ERROR_WANT_WRITE)
	{
		m_ssl_want_write_for_recv.store(true, std::memory_order_release);
		enable_mask(ACE_Event_Handler::WRITE_MASK);
	}
}

int SocketStream::enable_mask(ACE_Reactor_Mask bit)
{
	if (auto r = this->reactor())
		return r->mask_ops(this, bit, ACE_Reactor::ADD_MASK);
	return -1;
}

int SocketStream::disable_mask(ACE_Reactor_Mask bit)
{
	if (auto r = this->reactor())
		return r->mask_ops(this, bit, ACE_Reactor::CLR_MASK);
	return -1;
}

void SocketStream::fire_connect()
{
	std::lock_guard<std::mutex> l(m_cb_mutex);
	if (m_connect_cb)
		m_connect_cb();
}

void SocketStream::fire_close()
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

void SocketStream::deliver_message(std::vector<std::uint8_t> &&msg)
{
	std::lock_guard<std::mutex> l(m_cb_mutex);
	if (m_data_cb)
		m_data_cb(std::move(msg));
}

void SocketStream::notify_sent(const std::unique_ptr<msgpack::sbuffer> &data)
{
	std::lock_guard<std::mutex> l(m_cb_mutex);
	if (m_send_cb)
		m_send_cb(data);
}

void SocketStream::report_error(const std::string &msg)
{
	LOG_ERR << "SocketStream error: " << msg << " | " << last_error_msg();
	std::lock_guard<std::mutex> l(m_cb_mutex);
	if (m_error_cb)
		m_error_cb(msg);
}
