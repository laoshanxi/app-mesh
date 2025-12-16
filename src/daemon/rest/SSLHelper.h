#pragma once

#include <string>

class ACE_SSL_Context;

namespace SSLHelper
{
    ACE_SSL_Context *initServerSSL(ACE_SSL_Context *context, const std::string &certFile, const std::string &keyFile, const std::string &caPath);
    ACE_SSL_Context *initClientSSL(ACE_SSL_Context *context, const std::string &certFile, const std::string &keyFile, const std::string &caPath);
}
