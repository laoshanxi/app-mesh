// src/daemon/rest/drogon/WsController.h
#ifndef DGN_WS_CONTROLLER_H
#define DGN_WS_CONTROLLER_H

#include <string>

#include <drogon/HttpFilter.h>
#include <drogon/WebSocketController.h>

namespace dgn
{
    // Sub-protocol advertised by App Mesh WebSocket clients.
    constexpr const char *WS_SUBPROTOCOL = "appmesh-ws";

    // Accepted sub-protocol for a client offer; "" when none is supported.
    std::string negotiateWsSubprotocol(const std::string &offered);

    // Runs on the WS upgrade request before the handshake completes. A
    // bearer-less request is accepted with only the loopback managed-worker
    // privilege; a bearer token is authenticated and its principal pinned.
    // Rejection answers the upgrade with HTTP 401 instead of completing the
    // handshake.
    class WsAuthFilter : public drogon::HttpFilter<WsAuthFilter>
    {
    public:
        void doFilter(const drogon::HttpRequestPtr &req,
                      drogon::FilterCallback &&fcb,
                      drogon::FilterChainCallback &&fccb) override;
    };

    // Catch-all WebSocket endpoint, registered by name through
    // registerWebSocketControllerRegex() in Adaptor.cpp. All frames carry
    // msgpack-serialized Request objects and share the REST worker pipeline.
    class WsController : public drogon::WebSocketController<WsController>
    {
    public:
        void handleNewConnection(const drogon::HttpRequestPtr &req,
                                 const drogon::WebSocketConnectionPtr &conn) override;
        void handleNewMessage(const drogon::WebSocketConnectionPtr &conn,
                              std::string &&message,
                              const drogon::WebSocketMessageType &type) override;
        void handleConnectionClosed(const drogon::WebSocketConnectionPtr &conn) override;

        // Referenced by the adaptor at registration time so this translation
        // unit is never dropped by the static-library linker.
        static const std::string &registrationName() { return classTypeName(); }

        // Routes are registered manually through
        // registerWebSocketControllerRegex(), so the static path list stays
        // empty; the macros only provide the initPathRouting() the base
        // template requires.
        WS_PATH_LIST_BEGIN
        WS_PATH_LIST_END
    };
}
#endif
