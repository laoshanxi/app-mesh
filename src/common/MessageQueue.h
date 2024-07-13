#include <ace/Message_Queue.h>
#include <ace/Synch.h>

class MessageQueue : public ACE_Message_Queue<ACE_MT_SYNCH>
{
public:
    MessageQueue();
    virtual ~MessageQueue();

    virtual bool is_full_i() override;
};
