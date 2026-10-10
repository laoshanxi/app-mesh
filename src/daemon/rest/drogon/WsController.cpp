// src/daemon/rest/drogon/WsController.cpp
#include "WsController.h"

#include <string>
#include <string_view>

#include "../../../common/StreamLogger.h"
#include "../../../common/Utility.h"
#include "../../security/Security.h"
#include "Adaptor.h"

namespace
{
    constexpr std::size_t MAX_JWT_TOKEN_LENGTH = 8 * 1024; // 8KB

    std::string trimToken(std::string_view token)
    {
        const auto begin = token.find_first_not_of(" \t");
        if (begin == std::string_view::npos)
            return {};
        const auto end = token.find_last_not_of(" \t");
        return std::string(token.substr(begin, end - begin + 1));
    }
}

namespace dgn
{
    std::string negotiateWsSubprotocol(const std::string &offered)
    {
        for (std::string_view rest(offered); !rest.empty();)
        {
            const auto comma = rest.find(',');
            const auto token = trimToken(rest.substr(0, comma));
            if (token == WS_SUBPROTOCOL)
                return token;
            if (comma == std::string_view::npos)
                break;
            rest.remove_prefix(comma + 1);
        }
        return {};
    }

    void WsAuthFilter::doFilter(const drogon::HttpRequestPtr &req,
                                drogon::FilterCallback &&fcb,
                                drogon::FilterChainCallback &&fccb)
    {
        // Reject an upgrade whose offered sub-protocols are all unsupported.
        const auto offered = req->getHeader(web::http::header_names::sec_websocket_protocol);
        if (!offered.empty() && negotiateWsSubprotocol(offered).empty())
        {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k400BadRequest);
            resp->setBody("Unsupported sub-protocol");
            // The abandoned upgrade socket carries a WS close frame; do not reuse it.
            resp->setCloseConnection(true);
            fcb(resp);
            return;
        }

        const auto &authorization = req->getHeader(web::http::header_names::authorization);
        if (authorization.empty())
        {
            // No bearer: no pinned principal; protected routes answer 401.
            req->attributes()->insert("principalId", std::string());
            fccb();
            return;
        }
        try
        {
            if (authorization.size() > MAX_JWT_TOKEN_LENGTH)
                throw std::domain_error("Authentication required");
            const auto principal = Security::authenticateBearerAuthorization(authorization);
            req->attributes()->insert("principalId", principal.id());
            fccb();
        }
        catch (...)
        {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k401Unauthorized);
            resp->addHeader(web::http::header_names::www_authenticate, "Bearer realm=\"appmesh\"");
            resp->setBody("Authentication required");
            resp->setCloseConnection(true);
            fcb(resp);
        }
    }

    void WsController::handleNewConnection(const drogon::HttpRequestPtr &req,
                                           const drogon::WebSocketConnectionPtr &conn)
    {
        const static char fname[] = "WsController::handleNewConnection() ";
        try
        {
            DrogonAdaptor::instance()->onWsOpen(req, conn);
        }
        catch (const std::exception &e)
        {
            LOG_ERR << fname << "exception: " << e.what();
            conn->shutdown(static_cast<drogon::CloseCode>(1011), "internal error");
        }
        catch (...)
        {
            // Escaping would terminate the trantor event loop.
            LOG_ERR << fname << "unknown exception";
            conn->shutdown(static_cast<drogon::CloseCode>(1011), "internal error");
        }
    }

    void WsController::handleNewMessage(const drogon::WebSocketConnectionPtr &conn,
                                        std::string &&message,
                                        const drogon::WebSocketMessageType &type)
    {
        const static char fname[] = "WsController::handleNewMessage() ";
        try
        {
            DrogonAdaptor::instance()->onWsMessage(conn, std::move(message), type);
        }
        catch (const std::exception &e)
        {
            LOG_ERR << fname << "exception: " << e.what();
            conn->shutdown(static_cast<drogon::CloseCode>(1011), "internal error");
        }
        catch (...)
        {
            LOG_ERR << fname << "unknown exception";
            conn->shutdown(static_cast<drogon::CloseCode>(1011), "internal error");
        }
    }

    void WsController::handleConnectionClosed(const drogon::WebSocketConnectionPtr &conn)
    {
        const static char fname[] = "WsController::handleConnectionClosed() ";
        try
        {
            DrogonAdaptor::instance()->onWsClose(conn);
        }
        catch (const std::exception &e)
        {
            LOG_ERR << fname << "exception: " << e.what();
        }
        catch (...)
        {
            // Nothing left to close; just do not escape.
            LOG_ERR << fname << "unknown exception";
        }
    }
}
