"""数字人客户端公共模块：构造 AppMeshClient + 调用技能/大脑。

App 命名约定: 技能 App 叫 <team>-<skill>，大脑 App 叫 <team>-agent。
team 来自环境变量 DH_TEAM（由 setup.sh 渲染进 App env / chat.py --team）。
"""

import json
import os
import sys

from appmesh import AppMeshClient


def team() -> str:
	return os.getenv("DH_TEAM", "demo")


def skill_app(name: str) -> str:
	return f"{team()}-{name}"


def agent_app() -> str:
	return f"{team()}-agent"


def make_client() -> AppMeshClient:
	token = os.getenv("APPMESH_BEARER_TOKEN")
	if not token:
		sys.exit("缺少 APPMESH_BEARER_TOKEN — 先 source env.sh 或自行设置")
	return AppMeshClient(
		base_url=os.getenv("APPMESH_URL", "https://127.0.0.1:6060"),
		ssl_verify=os.getenv("APPMESH_CA") or None,
		bearer_token=token,
	)


def call_skill(client: AppMeshClient, name: str, payload: dict, timeout: int = 60) -> dict:
	"""run_task 调一个技能 App（自动加 team 前缀），返回解析后的 JSON dict。"""
	raw = client.run_task(app_name=skill_app(name), data=json.dumps(payload, ensure_ascii=False), timeout=timeout)
	try:
		return json.loads(raw)
	except (TypeError, ValueError):
		return {"status": "error", "message": "non-JSON result", "raw": str(raw)}


def send_turn(client: AppMeshClient, session_id: str, text: str, timeout: int = 300) -> dict:
	"""向大脑（<team>-agent）发一轮对话（session_send），返回完整 JSON 响应。"""
	payload = {"action": "session_send", "session_id": session_id, "input": text}
	raw = client.run_task(app_name=agent_app(), data=json.dumps(payload, ensure_ascii=False), timeout=timeout)
	return json.loads(raw)
