// src/common/os/sysinfo.cpp
// Platform-agnostic sysinfo utilities (constructors, operators).

#include "sysinfo.h"

namespace os
{

	Memory::Memory()
		: total_bytes(0), free_bytes(0), available_bytes(0), total_swap_bytes(0), free_swap_bytes(0), swap_available(false)
	{
	}

	std::ostream &operator<<(std::ostream &stream, const Memory &mem)
	{
		return stream << "Memory [total_bytes <" << mem.total_bytes << "> "
					  << "free_bytes <" << mem.free_bytes << "> "
					  << "available_bytes <" << mem.available_bytes << "> "
					  << "total_swap_bytes <" << mem.total_swap_bytes << "> "
					  << "free_swap_bytes <" << mem.free_swap_bytes << ">]";
	}

	CPU::CPU(unsigned int _id, unsigned int _core, unsigned int _socket) : id(_id), core(_core), socket(_socket) {}

	std::ostream &operator<<(std::ostream &stream, const CPU &cpu)
	{
		return stream << "CPU [id <" << cpu.id << "> "
					  << "core <" << cpu.core << "> "
					  << "socket <" << cpu.socket << ">]";
	}

} // namespace os
