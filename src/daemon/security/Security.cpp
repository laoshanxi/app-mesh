#include "Security.h"

#include "../../common/Utility.h"
#include "SecurityConsul.h"
#include "SecurityJson.h"
#include "SecurityKeycloak.h"
#include "ldapplugin/SecurityLDAP.h"

std::shared_ptr<Security> Security::m_instance = nullptr;
std::recursive_mutex Security::m_mutex;

void Security::init(const std::string &interface)
{
    const static char fname[] = "Security::init() ";
    LOG_INF << fname << "Initializing security plugin: " << interface;

    std::shared_ptr<Security> instance;
    if (interface == JSON_KEY_USER_key_method_local)
    {
        instance = std::make_shared<SecurityJson>();
    }
    else if (interface == JSON_KEY_USER_key_method_oauth2)
    {
        instance = std::make_shared<SecurityKeycloak>();
    }
    else if (interface == JSON_KEY_USER_key_method_consul)
    {
        instance = std::make_shared<SecurityConsul>();
    }
    else if (interface == JSON_KEY_USER_key_method_ldap)
    {
        instance = std::make_shared<SecurityLDAP>();
    }
    else
    {
        throw std::invalid_argument(fname + std::string("Unsupported security plugin: ") + interface);
    }

    try
    {
        instance->init();
        Security::instance(std::move(instance));
        LOG_INF << fname << "Security plugin initialized successfully";
    }
    catch (const std::exception &ex)
    {
        LOG_ERR << fname << "Exception during security initialization: " << ex.what();
        throw;
    }
}

std::shared_ptr<Security> Security::instance()
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    if (!m_instance)
    {
        LOG_ERR << "Security::instance() called before initialization";
    }
    return m_instance;
}

void Security::instance(std::shared_ptr<Security> instance)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    m_instance = instance;
}
