#include <chrono>
#include <tuple>

#include "../../../common/Utility.h"
#include "ProtobufHelper.h"

// The first 4 bytes of the protocol buffer data contains the size of the following body data.
constexpr size_t PROTOBUF_HEADER_LENGTH = 4;

const std::tuple<std::shared_ptr<char>, size_t> ProtobufHelper::serialize(const google::protobuf::Message &msg)
{
    const auto msgLength = msg.ByteSizeLong();
    const auto totalLength = PROTOBUF_HEADER_LENGTH + msgLength;
    const auto buffer = make_shared_array<char>(totalLength);

    google::protobuf::io::ArrayOutputStream outputStream(buffer.get(), totalLength);
    google::protobuf::io::CodedOutputStream codedOut(&outputStream);
    codedOut.WriteVarint32(msgLength);     // write header
    msg.SerializeToCodedStream(&codedOut); // write body

    return std::make_tuple(buffer, totalLength); // return buffer and length pair
}

bool ProtobufHelper::deserialize(google::protobuf::Message &msg, const char *data)
{
    const static char fname[] = "ProtobufHelper::deserialize() ";

    // TODO: sizeof(data) should pass from outside, due to ACE_Message_Block can not pass
    //  more parameters, so parse header again
    const auto dataSize = deserializeHeader(data) + PROTOBUF_HEADER_LENGTH;

    // Re-read the input length from header
    google::protobuf::io::ArrayInputStream arrayInput(data, dataSize);
    google::protobuf::io::CodedInputStream codedInput(&arrayInput);

    // Read an unsigned integer with variant encoding, truncating to 32 bits.
    google::protobuf::uint32 bodySize = 0;
    if (!codedInput.ReadVarint32(&bodySize) && bodySize > 0)
    {
        LOG_ERR << fname << "parse body length failed with error :" << std::strerror(errno);
        return false;
    }

    // Read the following body of the message
    google::protobuf::io::CodedInputStream::Limit msgLimit = codedInput.PushLimit(bodySize);

    // De-Serialize
    if (!msg.ParseFromCodedStream(&codedInput))
    {
        LOG_ERR << fname << "ParseFromCodedStream failed with error :" << std::strerror(errno);
        return false;
    }

    // undo the limit
    codedInput.PopLimit(msgLimit);
    return true;
}

size_t ProtobufHelper::deserializeHeader(const char *data)
{
    const static char fname[] = "ProtobufHelper::deserializeHeader() ";

    char buffer[PROTOBUF_HEADER_LENGTH];
    memcpy(buffer, data, PROTOBUF_HEADER_LENGTH); // copy to local buffer to parse header

    google::protobuf::io::ArrayInputStream arrayInput(buffer, PROTOBUF_HEADER_LENGTH);
    google::protobuf::io::CodedInputStream codedInput(&arrayInput);
    google::protobuf::uint32 bodySize = 0;
    if (codedInput.ReadVarint32(&bodySize))
    {
        LOG_INF << fname << "read body size from header:" << bodySize;
        return bodySize;
    }
    else
    {
        LOG_ERR << fname << "parse header length failed with error :" << std::strerror(errno);
        return 0;
    }
}

const std::tuple<char *, size_t> ProtobufHelper::readMessageBlock(const ACE_SOCK_Stream &socket)
{
    const static char fname[] = "ProtobufHelper::readMessageBlock() ";
    LOG_DBG << fname << "entered";

    // 1. read header socket data (4 bytes), use MSG_PEEK to not clear data from cache
    char header[PROTOBUF_HEADER_LENGTH] = {0};
    if (socket.get_handle() != ACE_INVALID_HANDLE && socket.recv_n(header, PROTOBUF_HEADER_LENGTH, MSG_PEEK) <= 0)
    {
        socket.dump();
        LOG_ERR << fname << "read header length failed with error :" << std::strerror(errno);
        return std::make_tuple(nullptr, 0);
    }

    // 2. parse header data (get body length)
    const auto bodySize = deserializeHeader(header);
    if (bodySize == 0)
    {
        socket.dump();
        LOG_ERR << fname << "parse header length with error :" << std::strerror(errno);
        return std::make_tuple(nullptr, 0);
    }

    // 3. read header + body socket data
    const auto bufferSize = bodySize + PROTOBUF_HEADER_LENGTH;
    auto bodyBuffer = new char[bufferSize];
    // static const ACE_Time_Value timeout(std::chrono::seconds(10));
    if (socket.get_handle() != ACE_INVALID_HANDLE && socket.recv_n(bodyBuffer, bufferSize) <= 0)
    {
        LOG_ERR << fname << "read body socket data failed with error :" << std::strerror(errno);
        return std::make_tuple(nullptr, 0);
    }
    LOG_DBG << fname << "read message block data with length: " << bufferSize;
    return std::make_tuple(bodyBuffer, bufferSize);
}
