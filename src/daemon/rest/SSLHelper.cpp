// src/daemon/rest/SSLHelper.cpp
#include "SSLHelper.h"
#include "../../common/Utility.h"

#ifdef __has_include
#if __has_include(<ace/SSL/SSL_Context.h>)
#include <ace/SSL/SSL_Context.h>
#else
#include <ace/SSL_Context.h>
#endif
#else
#include <ace/SSL/SSL_Context.h>
#endif
namespace SSLHelper
{
    ACE_SSL_Context *initServerSSL(ACE_SSL_Context *context, const std::string &cert, const std::string &key, const std::string &ca)
    {
        const static char fname[] = "SSL::initServerSSL() ";

        LOG_INF << fname << "Init SSL with CA <" << ca << "> server cert <" << cert << "> server private key <" << key << ">";

        // Set server mode, allow TLSv1.2 and TLSv1.3 only
        context->set_mode(ACE_SSL_Context::SSLv23_server); // SSLv23_server enables TLS negotiation
        context->filter_versions(TCP_SSL_VERSION_LIST);    // "tlsv1.2,tlsv1.3"

        // Load server certificate and private key
#if defined(COMPILER_LOWER_EQUAL_485)
        if (context->certificate(cert.c_str(), SSL_FILETYPE_PEM) != 0)
#else
        if (context->certificate_chain(cert.c_str(), SSL_FILETYPE_PEM) != 0)
#endif
        {
            LOG_ERR << fname << "Failed to load certificate: " << last_error_msg();
            return nullptr;
        }
        if (context->private_key(key.c_str(), SSL_FILETYPE_PEM) != 0 || context->verify_private_key() != 0)
        {
            LOG_ERR << fname << "Failed to load private key: " << last_error_msg();
            return nullptr;
        }

        // Enable forward secrecy for TLS1.2 (ECDH curve selection)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        // SSL_CTX_set_ecdh_auto is deprecated (no-op) in OpenSSL 1.1+; use explicit curve list
        if (!SSL_CTX_set1_curves_list(context->context(), "X25519:P-256:P-384"))
        {
            LOG_WAR << fname << "SSL_CTX_set1_curves_list failed: " << last_error_msg();
        }
#else
        if (!SSL_CTX_set_ecdh_auto(context->context(), 1))
        {
            LOG_WAR << fname << "SSL_CTX_set_ecdh_auto failed: " << last_error_msg();
        }
#endif

        // Configure cipher suites to prioritize security, explicitly excluding weak ciphers
        const char *tls12Ciphers = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5";
        if (!SSL_CTX_set_cipher_list(context->context(), tls12Ciphers))
        {
            LOG_WAR << fname << "SSL_CTX_set_cipher_list failed: " << last_error_msg();
        }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        const char *tls13Ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        if (!SSL_CTX_set_ciphersuites(context->context(), tls13Ciphers))
        {
            LOG_WAR << fname << "SSL_CTX_set_ciphersuites failed: " << last_error_msg();
        }
#endif

        // Disable unsafe legacy renegotiation
        SSL_CTX_clear_options(context->context(), SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

        // Set client certificate verification if required
        if (!ca.empty())
        {
            context->set_verify_peer(true, 1 /* verify once */, 9 /* standard verification depth */);

            // Load trusted CA certificates if the CA path is accessible
            if (ACE_OS::access(ca.c_str(), R_OK) == 0)
            {
                bool isDir = Utility::isDirExist(ca);
                if (context->load_trusted_ca(isDir ? 0 : ca.c_str(), isDir ? ca.c_str() : 0, false) != 0)
                {
                    LOG_WAR << fname << "Failed to load trusted CA from: " << ca;
                }

                // Set verify mode and callback explicitly for the SSL context
                SSL_CTX_set_verify(context->context(), context->default_verify_mode(), context->default_verify_callback());
            }
            else
            {
                LOG_WAR << fname << "CA path inaccessible or invalid: " << ca;
            }
        }

        // Configure session caching and lifetime to improve TLS session resumption performance
        static const unsigned char sess_id_ctx[] = "appmesh-tcp";
        SSL_CTX_set_session_id_context(context->context(), sess_id_ctx, sizeof(sess_id_ctx) - 1);
        SSL_CTX_set_session_cache_mode(context->context(), SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_timeout(context->context(), 300); // 5-minute session timeout

        return context;
    }

    ACE_SSL_Context *initClientSSL(ACE_SSL_Context *context, const std::string &cert, const std::string &key, const std::string &ca, bool verifyPeer)
    {
        const static char fname[] = "SSL::initClientSSL() ";

        LOG_INF << fname << "Init SSL with CA <" << ca << "> client cert <" << cert << "> client private key <" << key << "> verifyPeer <" << verifyPeer << ">";

        context->set_mode(ACE_SSL_Context::SSLv23_client);
        context->filter_versions(TCP_SSL_VERSION_LIST);

        const char *tls12Ciphers = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5";
        if (!SSL_CTX_set_cipher_list(context->context(), tls12Ciphers))
        {
            LOG_WAR << fname << "SSL_CTX_set_cipher_list failed: " << last_error_msg();
        }
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        const char *tls13Ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        if (!SSL_CTX_set_ciphersuites(context->context(), tls13Ciphers))
        {
            LOG_WAR << fname << "SSL_CTX_set_ciphersuites failed: " << last_error_msg();
        }
#endif

        if (!ca.empty())
        {
            if (ACE_OS::access(ca.c_str(), R_OK) == 0)
            {
                bool isDir = Utility::isDirExist(ca);
                if (context->load_trusted_ca(isDir ? 0 : ca.c_str(), isDir ? ca.c_str() : 0, false) != 0)
                {
                    LOG_WAR << fname << "Failed to load trusted CA from: " << ca;
                    return nullptr;
                }
            }
            else
            {
                LOG_WAR << fname << "CA path inaccessible or invalid: " << ca;
                return nullptr;
            }
        }

        if (!cert.empty() && !key.empty())
        {
            if (context->certificate(cert.c_str(), SSL_FILETYPE_PEM) == -1 ||
                context->private_key(key.c_str(), SSL_FILETYPE_PEM) == -1)
            {
                LOG_ERR << fname << "Failed to load certificate " << cert << " and/or private key " << key;
                return nullptr;
            }
        }

        if (verifyPeer)
        {
            context->set_verify_peer(true, 1 /* verify once */, 9 /* standard depth */);
            LOG_INF << fname << "Peer certificate verification enabled";
        }
        else
        {
            LOG_INF << fname << "Peer certificate verification disabled";
        }

        return context;
    }
}
