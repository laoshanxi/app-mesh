"""sys-info 技能：查询数字人所在节点的实时状态。入参 {} 即可。"""

import os
import platform
import shutil
import socket

from common import serve


def _sysconf(name):
	try:
		return os.sysconf(name)
	except (ValueError, OSError):  # 部分容器/平台不暴露该参数
		return 0


def handler(_request):
	usage = shutil.disk_usage("/")
	mem_bytes = _sysconf("SC_PAGE_SIZE") * _sysconf("SC_PHYS_PAGES")
	cpu = os.cpu_count() or 0
	load1 = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
	return {
		"status": "ok",
		"data": {
			"hostname": socket.gethostname(),
			"platform": platform.platform(),
			"python": platform.python_version(),
			"cpu_count": cpu,
			"loadavg_1m": round(load1, 2),
			"memory_gb": round(mem_bytes / 1024**3, 1),
			"disk_root": {
				"total_gb": round(usage.total / 1024**3, 1),
				"free_gb": round(usage.free / 1024**3, 1),
			},
		},
	}


if __name__ == "__main__":
	serve(handler)
