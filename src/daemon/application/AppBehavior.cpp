#include "AppBehavior.h"
#include "../../common/Utility.h"

AppBehavior::AppBehavior()
    : m_exitEvent(AppBehavior::Action::STANDBY)
{
}

void AppBehavior::behaviorInit(nlohmann::json config)
{
    m_exitEvent = AppBehavior::Action::STANDBY;
    m_exitCodeEvent.clear();
    if (!config.is_null())
    {
        auto exit = GET_JSON_STR_VALUE(config, JSON_KEY_APP_behavior_exit);
        if (exit.length())
        {
            m_exitEvent = str2action(exit);
        }
        if (HAS_JSON_FIELD(config, JSON_KEY_APP_behavior_control))
        {
            auto jsonObj = config[JSON_KEY_APP_behavior_control];
            for (auto &event : jsonObj.items())
            {
                if (Utility::isNumber(event.key()))
                {
                    m_exitCodeEvent[std::atoi(event.key().c_str())] = str2action(event.value().get<std::string>());
                }
                else
                {
                    LOG_ERR << "invalid control code <" << event.key() << ">";
                    throw std::invalid_argument("invalid control code");
                }
            }
        }
    }
}

nlohmann::json AppBehavior::behaviorAsJson()
{
    nlohmann::json result;
    result[JSON_KEY_APP_behavior_exit] = std::string(action2str(m_exitEvent));
    if (m_exitCodeEvent.size())
    {
        nlohmann::json controls;
        for (const auto &control : m_exitCodeEvent)
        {
            controls[std::to_string(control.first)] = std::string(action2str(control.second));
        }
        result[JSON_KEY_APP_behavior_control] = std::move(controls);
    }
    return result;
}

AppBehavior::Action AppBehavior::str2action(const std::string &action2str)
{
    if (Utility::strTolower(action2str) == JSON_KEY_APP_behavior_standby)
    {
        return AppBehavior::Action::STANDBY;
    }
    else if (Utility::strTolower(action2str) == JSON_KEY_APP_behavior_restart)
    {
        return AppBehavior::Action::RESTART;
    }
    else if (Utility::strTolower(action2str) == JSON_KEY_APP_behavior_keepalive)
    {
        return AppBehavior::Action::KEEPALIVE;
    }
    else if (Utility::strTolower(action2str) == JSON_KEY_APP_behavior_remove)
    {
        return AppBehavior::Action::REMOVE;
    }
    LOG_WAR << "invalid action input <" << action2str << ">";
    throw std::invalid_argument("invalid action input");
}

std::string AppBehavior::action2str(AppBehavior::Action action)
{
    static std::string array[] = {
        JSON_KEY_APP_behavior_standby,
        JSON_KEY_APP_behavior_restart,
        JSON_KEY_APP_behavior_keepalive,
        JSON_KEY_APP_behavior_remove};
    return array[(int)action];
}

AppBehavior::Action AppBehavior::exitAction(int code)
{
    if (m_exitCodeEvent.count(code))
    {
        return m_exitCodeEvent[code];
    }
    return m_exitEvent;
}
