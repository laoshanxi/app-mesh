#include <map>
#include <string>

#include <cpprest/json.h>

/// <summary>
/// Application error handling
/// </summary>
class AppBehavior
{
public:
    /// <summary>
    /// Application error handling behavior
    /// </summary>
    enum Action
    {
        STANDBY = 0,
        RESTART = 1,
        KEEPALIVE = 2,
        REMOVE = 3
    };

public:
    AppBehavior();
    virtual ~AppBehavior(){};

    static std::string action2str(AppBehavior::Action action);
    static AppBehavior::Action str2action(const std::string &action2str);

protected:
    void behaviorInit(web::json::value config);
    web::json::value behaviorAsJson();

    // behavior getting
    AppBehavior::Action exitAction(int code);

protected:
    // action for exit code beside m_exitCodeEvent
    AppBehavior::Action m_exitEvent;
    // key: exit code, Value: action
    std::map<int, AppBehavior::Action> m_exitCodeEvent;
};
