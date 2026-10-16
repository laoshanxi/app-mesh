#!/usr/bin/env python3
"""命令行调用一个技能: python3 call_skill.py <name> '<json 参数>'。

name 不带 team 前缀（由 DH_TEAM 环境变量补充，默认 demo）。
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dh_client import call_skill, make_client


def main():
	if len(sys.argv) < 2 or len(sys.argv) > 3:
		sys.exit("usage: call_skill.py <name> '<json>'")
	name = sys.argv[1]
	try:
		payload = json.loads(sys.argv[2]) if len(sys.argv) == 3 else {}
	except ValueError as exc:
		sys.exit(f"payload 不是合法 JSON: {exc}")
	if not isinstance(payload, dict):
		sys.exit("payload 必须是 JSON 对象")
	result = call_skill(make_client(), name, payload)
	print(json.dumps(result, ensure_ascii=False, indent=2))
	sys.exit(0 if result.get("status") == "ok" else 1)


if __name__ == "__main__":
	main()
