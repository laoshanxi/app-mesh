// src/daemon/rest/drogon/FrameCodec.h
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <mstcpip.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#include <trantor/utils/MsgBuffer.h>

#include "../../../common/Utility.h"

// Length-prefixed msgpack/raw framing shared by the inbound (TcpAdaptor) and
// outbound (TcpClientStream) TCP transports: 8-byte header (4-byte magic +
// 4-byte body length, network byte order) followed by the payload.
namespace tcpframe
{
    // Largest single frame body: an inline HTTP body (128MB) plus envelope.
    // Bounds the buffer wait for a declared length.
    constexpr std::size_t MAX_FRAME_BODY_SIZE = 256UL * 1024 * 1024;

    // Short keepalive probes: a peer that dies without a FIN must not look open.
    inline void enableKeepAlive(int fd)
    {
        if (fd < 0)
            return;
#ifdef _WIN32
        tcp_keepalive keepAlive{1, 5000, 2000};
        DWORD returned = 0;
        WSAIoctl(fd, SIO_KEEPALIVE_VALS, &keepAlive, sizeof(keepAlive), nullptr, 0, &returned, nullptr, nullptr);
#else
        int on = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) != 0)
            return;
        int idleSeconds = 5;
        int intervalSeconds = 2;
        int probes = 2;
#if defined(__APPLE__)
        // Darwin: TCP_KEEPALIVE (seconds).
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idleSeconds, sizeof(idleSeconds));
#else
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idleSeconds, sizeof(idleSeconds));
#endif
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intervalSeconds, sizeof(intervalSeconds));
        ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes));
#endif
    }

    // Appends one framed message (header + payload) to the buffer.
    inline void appendFrame(trantor::MsgBuffer &buf, const void *data, std::size_t len)
    {
        buf.appendInt32(TCP_MESSAGE_MAGIC);
        buf.appendInt32(static_cast<uint32_t>(len));
        if (len > 0)
            buf.append(static_cast<const char *>(data), len);
    }

    // Writes one frame header into dst (>= TCP_MESSAGE_HEADER_LENGTH bytes).
    inline void writeHeader(char *dst, std::size_t len)
    {
        trantor::MsgBuffer header;
        header.appendInt32(TCP_MESSAGE_MAGIC);
        header.appendInt32(static_cast<uint32_t>(len));
        std::memcpy(dst, header.peek(), TCP_MESSAGE_HEADER_LENGTH);
    }

    // Drains every complete frame from buf, invoking cb(payload, len) per
    // frame. Returns false on a protocol violation (bad magic or oversize
    // declared length); the caller must close the connection.
    template <typename F>
    inline bool drainFrames(trantor::MsgBuffer &buf, F &&cb)
    {
        auto peekU32 = [](const char *p) -> uint32_t
        {
            const auto *b = reinterpret_cast<const unsigned char *>(p);
            return (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | uint32_t(b[3]);
        };

        while (buf.readableBytes() >= TCP_MESSAGE_HEADER_LENGTH)
        {
            const uint32_t magic = peekU32(buf.peek());
            const uint32_t bodyLen = peekU32(buf.peek() + 4);
            if (magic != TCP_MESSAGE_MAGIC || bodyLen > MAX_FRAME_BODY_SIZE)
                return false;
            if (buf.readableBytes() < TCP_MESSAGE_HEADER_LENGTH + bodyLen)
                return true; // partial frame, wait for more data

            buf.retrieve(TCP_MESSAGE_HEADER_LENGTH);
            cb(buf.peek(), bodyLen);
            buf.retrieve(bodyLen);
        }
        return true;
    }
}
