#pragma once

#include "SecurityJson.h"

/**
 * @brief Security implementation using Consul storage
 */
class SecurityConsul : public SecurityJson
{
public:
    SecurityConsul();
    virtual ~SecurityConsul() override;
    virtual void init() override;

    void save() override;
};
