// src/common/os/linux.h
// Backward-compatibility header. Includes all OS domain headers.
// New code should include the specific domain header it needs:
//   process.h, sysinfo.h, filesystem.h, user.h
#pragma once

#include "filesystem.h"
#include "process.h"
#include "sysinfo.h"
#include "user.h"
