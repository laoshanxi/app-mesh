#pragma once

#include <list>
#include <memory>
#include <ostream>
#include <set>

#include "../Utility.h"
#include "linux.hpp"
#include "process.hpp"

namespace os
{
    class ProcessTree
    {
    public:
        // Returns a process subtree rooted at the specified PID, or none if
        // the specified pid could not be found in this process tree.
        std::shared_ptr<ProcessTree> find(pid_t pid) const;

        // Count the total RES memory usage in the process tree
        uint64_t totalRssMemBytes() const;

        uint64_t totalFileDescriptors() const;

        // get total CPU time
        uint64_t totalCpuTime() const;

        std::list<os::Process> getProcesses() const;

        pid_t findLeafPid() const;

        // Checks if the specified pid is contained in this process tree.
        bool contains(pid_t pid) const;

        operator Process() const;
        operator pid_t() const;

        const Process process;
        const std::list<ProcessTree> children;

    private:
        friend std::shared_ptr<ProcessTree> pstree(pid_t, const std::list<Process> &);

        ProcessTree(const Process &_process, const std::list<ProcessTree> &_children);
    };

    std::ostream &operator<<(std::ostream &stream, const ProcessTree &tree);
    std::ostream &operator<<(std::ostream &stream, const std::list<os::ProcessTree> &list);

    // Returns a process tree rooted at the specified pid using the
    // specified list of processes (or an error if one occurs).
    std::shared_ptr<ProcessTree> pstree(pid_t pid, const std::list<Process> &processes);

    // Returns a process tree for the specified pid (or all processes if
    // pid is none or the current process if pid is 0).
    std::shared_ptr<ProcessTree> pstree(pid_t pid = 0, void *ptree = nullptr);

} // namespace os
