#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/common/DateTime.h"
#include "../../src/common/Utility.h"
#include "../../src/daemon/security/Security.h"
#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <catch.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <ldapc++/cldap.h>
#include <log4cpp/Appender.hh>
#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/Priority.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <set>
#include <string>
#include <thread>
#include <time.h>

TEST_CASE("ldapcpp Test", "[security]")
{

    SECTION("MFA")
    {
        User u("2fa");
        std::cout << "MFA secret key: " << u.totpGenerateKey() << std::endl;
    }

    SECTION("password verification")
    {
        Ldap::Server ldap;
        bool success;
        ldap.Connect("ldap://127.0.0.1:389");
        std::cout << "ldap connect: " << ldap.Message() << std::endl;

        success = ldap.Bind("cn=admin,ou=users,dc=example,dc=org", "admin123");
        std::cout << "user <admin> bind success: " << success << std::endl;

        success = ldap.Bind("cn=mesh,ou=users,dc=example,dc=org", "mesh123");
        std::cout << "user <mesh> bind success: " << success << std::endl;

        success = ldap.Bind("cn=user,ou=users,dc=example,dc=org", "user123");
        std::cout << "user <user> bind success: " << success << std::endl;
    }

    SECTION("search")
    {
        Ldap::Server ldap;
        bool success;
        ldap.Connect("ldap://127.0.0.1:389");
        std::cout << "ldap connect: " << ldap.Message() << std::endl;

        success = ldap.Bind("cn=admin,dc=example,dc=org", "admin");
        std::cout << "user <admin> bind success: " << success << std::endl;

        // success = ldap.Bind("cn=admin,ou=users,dc=example,dc=org", "admin123");
        // std::cout << "user <admin> bind success: " << success << std::endl;

        // Base64::SetBinaryOnly(true);
        //  Search mush bind LDAP Administrator user
        auto result = ldap.Search("ou=users,dc=example,dc=org", Ldap::ScopeTree, "sn=*");
        std::cout << "search developers: " << result.size() << std::endl;
        for (auto &entry : result)
        {
            std::cout << "user: " << entry.DN() << std::endl;
            std::cout << " - sn:" << entry.GetStringValue("sn") << std::endl;
            std::cout << " - gidNumber:" << entry.GetStringValue("gidNumber") << std::endl;
            std::cout << " - mail:" << entry.GetStringValue("mail") << std::endl;
        }
    }
}
