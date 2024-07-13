#include "MessageQueue.h"

MessageQueue::MessageQueue()
{
}

MessageQueue::~MessageQueue()
{
}

bool MessageQueue::is_full_i()
{
    // ignore the hwm/lwm for infinite capacity
    return false;
}
