#!/usr/bin/env python3
"""数字人终端入口（Phase 0 聊天 & 技能调试）。

用法:
  ./chat.py --team demo                                # 交互聊天（需要大脑已部署）
  ./chat.py --team demo --skill kb-search '{"query":"报销"}'   # 直接调技能（不需要模型）
交互命令: /skill <名> '<json>' 直接调技能 · /quit 退出
"""

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "skills"))

from dh_client import agent_app, call_skill, make_client, send_turn, team  # noqa: E402


def print_turn(response):
	if response.get("status") != "ok":
		print(f"[错误] {json.dumps(response, ensure_ascii=False)}")
		return
	data = response.get("data") or {}
	print(data.get("answer", json.dumps(data, ensure_ascii=False)))


def main():
	parser = argparse.ArgumentParser(description="数字人终端入口")
	parser.add_argument("--team", default=team(), help="team 名（App 前缀），默认 DH_TEAM 或 demo")
	parser.add_argument("--session", default=None, help="复用指定会话 id（继续上次的对话）")
	parser.add_argument("--skill", metavar="NAME", help="一次性调用技能后退出，不经过模型")
	parser.add_argument("payload", nargs="?", default="{}", help="--skill 的 JSON 参数")
	args = parser.parse_args()

	os.environ["DH_TEAM"] = args.team
	client = make_client()

	if args.skill:
		try:
			payload = json.loads(args.payload)
		except ValueError as exc:
			sys.exit(f"payload 不是合法 JSON: {exc}")
		if not isinstance(payload, dict):
			sys.exit("payload 必须是 JSON 对象")
		print(json.dumps(call_skill(client, args.skill, payload), ensure_ascii=False, indent=2))
		return

	session = args.session or str(uuid.uuid4())
	print(f"数字人终端 · team={args.team} · agent={agent_app()} · session={session}")
	print("直接输入内容对话；/skill <名> '<json>' 直接调技能；/quit 退出。")
	while True:
		try:
			text = input("\n你> ").strip()
		except (EOFError, KeyboardInterrupt):
			print()
			return
		if not text:
			continue
		if text == "/quit":
			return
		if text.startswith("/skill "):
			_, rest = text.split(" ", 1)
			name, _, payload = rest.partition(" ")
			try:
				result = call_skill(client, name.strip(), json.loads(payload or "{}"))
			except ValueError as exc:
				print(f"payload 不是合法 JSON: {exc}")
				continue
			print(json.dumps(result, ensure_ascii=False, indent=2))
			continue
		try:
			print_turn(send_turn(client, session, text))
		except Exception as exc:  # 网关/daemon 错误不打断会话
			print(f"[错误] {exc}")


if __name__ == "__main__":
	main()
