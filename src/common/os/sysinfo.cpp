// src/common/os/sysinfo.cpp
// Platform-agnostic sysinfo utilities (constructors, operators).

#include "sysinfo.h"

namespace os
{

	Memory::Memory() : total_bytes(0), free_bytes(0), totalSwap_bytes(0), freeSwap_bytes(0) {}

	std::ostream &operator<<(std::ostream &stream, const Memory &mem)
	{
		return stream << "Memory [total_bytes <" << mem.total_bytes << "> "
					  << "free_bytes <" << mem.free_bytes << "> "
					  << "totalSwap_bytes <" << mem.totalSwap_bytes << "> "
					  << "freeSwap_bytes <" << mem.freeSwap_bytes << ">]";
	}

	CPU::CPU(unsigned int _id, unsigned int _core, unsigned int _socket)
		: id(_id), core(_core), socket(_socket) {}

	std::ostream &operator<<(std::ostream &stream, const CPU &cpu)
	{
		return stream << "CPU [id <" << cpu.id << "> "
					  << "core <" << cpu.core << "> "
					  << "socket <" << cpu.socket << ">]";
	}

} // namespace os
