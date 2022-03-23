#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <ace/Message_Block.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Stream.h>

#include "../../common/TimerHandler.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "protoc/Response.pb.h"

/// <summary>
/// REST Server Object, forward http REST request to TCP Server side
/// </summary>
class RestChildObject : public ACE_SOCK_Connector, public RestHandler, public TimerHandler
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
    void replyResponse(const appmesh::Response &response);

    void onResponseTimeout(int timerId);

private:
    ACE_SOCK_Stream m_socketStream;
    // key: message uuid; value: message
    std::map<std::string, HttpRequest> m_clientRequests;
    // key: message uuid; value: timer id
    std::map<std::string, int> m_clientRequestsTimer;
    mutable std::recursive_mutex m_mutex;
    static std::shared_ptr<RestChildObject> m_instance;
};
