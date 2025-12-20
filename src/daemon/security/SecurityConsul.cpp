// src/daemon/security/SecurityConsul.cpp
#include "SecurityConsul.h"
#include "../../common/Utility.h"
#include "ConsulConnection.h"

SecurityConsul::SecurityConsul() = default;
SecurityConsul::~SecurityConsul() = default;

void SecurityConsul::init()
{
    const static char fname[] = "SecurityConsul::init() ";

    ConsulConnection::instance()->initialize();
    auto config = ConsulConnection::instance()->fetchSecurityJson();
    m_jsonSecurity = JsonSecurity::FromJson(config);
    if (m_jsonSecurity->m_users->getUsers().empty())
    {
        throw std::invalid_argument("No security information found in Consul");
    }

    LOG_INF << fname << "Security information successfully retrieved from Consul";
}

void SecurityConsul::save()
{
    const static char fname[] = "SecurityConsul::save() ";

    try
    {
        ConsulConnection::instance()->saveSecurity(this->AsJson());
        LOG_INF << fname << "Security information successfully saved to Consul";
    }
    catch (const std::exception &ex)
    {
        LOG_ERR << fname << "Failed to save security information: " << ex.what();
        throw;
    }
}