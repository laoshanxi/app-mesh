#pragma once
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <ace/Message_Block.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Stream.h>

#include "HttpRequest.h"
#include "PrometheusRest.h"

class RestChildObject : public ACE_SOCK_Connector, public PrometheusRest
{
public:
    RestChildObject();
    virtual ~RestChildObject();

    static std::shared_ptr<RestChildObject> instance();
    static void instance(std::shared_ptr<RestChildObject> restClientObj);

    void connectAndRun(int port);
    void sendRequest2Server(const HttpRequest &message);
    void replyResponse(ACE_Message_Block *msg);
    static ACE_Message_Block *readMessageBlock(const ACE_SOCK_Stream &socket);

private:
    ACE_Message_Block *readRequestMessage();

private:
    ACE_SOCK_Stream m_socketStream;
    // key: message uuid; value: message
    std::map<std::string, HttpRequest> m_sentMessages;
    mutable std::recursive_mutex m_mutex;
    static std::shared_ptr<RestChildObject> m_instance;
};
