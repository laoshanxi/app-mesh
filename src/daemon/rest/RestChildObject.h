#pragma once
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <ace/Message_Block.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Stream.h>

#include "HttpRequest.h"
#include "RestHandler.h"

/// <summary>
/// REST Server Object, forward http REST request to TCP Server side
/// </summary>
class RestChildObject : public ACE_SOCK_Connector, public RestHandler
{
public:
    RestChildObject();
    virtual ~RestChildObject();

    static std::shared_ptr<RestChildObject> instance();
    static void instance(std::shared_ptr<RestChildObject> restClientObj);

    /// <summary>
    /// Connect to TCP REST Server and block read REST response from TCP side.
    /// </summary>
    /// <param name="port"></param>
    void connectAndRun(int port);

    /// <summary>
    /// Send REST request to TCP Server side and cache HttpRequest for replyResponse()
    /// </summary>
    /// <param name="message"></param>
    void sendRequest2Server(const HttpRequest &message);

    /// <summary>
    /// Reply REST Response
    /// </summary>
    /// <param name="msg"></param>
    void replyResponse(ACE_Message_Block *response);

    /// <summary>
    /// Read Message Block from Socket Stream
    /// </summary>
    /// <param name="socket"></param>
    /// <returns></returns>
    static ACE_Message_Block *readMessageBlock(const ACE_SOCK_Stream &socket);

private:
    ACE_SOCK_Stream m_socketStream;
    // key: message uuid; value: message
    std::map<std::string, HttpRequest> m_sentMessages;
    mutable std::recursive_mutex m_mutex;
    static std::shared_ptr<RestChildObject> m_instance;
};
