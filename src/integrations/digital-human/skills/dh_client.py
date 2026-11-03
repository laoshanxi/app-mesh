"""数字人客户端公共模块：构造 AppMeshClient + 调用技能/大脑。

App 命名约定: 技能 App 叫 <team>-<skill>，大脑 App 叫 <team>-agent。
team 来自环境变量 DH_TEAM（由 setup.sh 渲染进 App env / chat.py --team）。

凭据两选一（token 生命周期交给 SDK）:
- APPMESH_BEARER_TOKEN          外部管理的静态 token（开发/一次性调用）
- DH_BOT_PASSWORD_FILE          密码文件（600），SDK 的 PasswordGrantProvider
  + DH_BOT_USER / DH_TOKEN_URL  负责铸造、过期前刷新、401 后重认证；文件每次
                                授予时重读，密码轮换免重启。
"""

import json
import os
from pathlib import Path

from appmesh import AppMeshClient, PasswordGrantProvider


def team() -> str:
	return os.getenv("DH_TEAM", "demo")


def skill_app(name: str) -> str:
	return f"{team()}-{name}"


def agent_app() -> str:
	return f"{team()}-agent"


def _discover_password_file():
	"""约定路径：setup.sh 为本 team 生成的密码文件（先专用账号，后管理员回退）。

	App 内由渲染的 env 显式指定；chat.py / skill 手工调用时按此约定自动发现。
	返回 (路径, 用户名) 或 (None, None)。文件缺失抛 RuntimeError。
	"""
	if os.getenv("DH_BOT_PASSWORD_FILE"):
		path = os.environ["DH_BOT_PASSWORD_FILE"]
		if not os.path.exists(path):
			raise RuntimeError(f"DH_BOT_PASSWORD_FILE 指向的文件不存在: {path}")
		return path, os.getenv("DH_BOT_USER", f"dh-bot@{team()}.local")
	pkg = Path(__file__).resolve().parent.parent
	for name, user in (("dh-bot.password", f"dh-bot@{team()}.local"), ("admin.password", "admin@appmesh.local")):
		candidate = pkg / "runtime" / team() / name
		if candidate.exists():
			return str(candidate), user
	return None, None


def _token_url() -> str:
	"""token 端点归一化：env 可写 base（与 appmesh-auth.sh 的 http://127.0.0.1:6062
	约定一致）或完整端点。SDK 的 PasswordGrantProvider.token_url 是完整端点语义
	（PyPI 3.0.10 与仓库 HEAD 一致；给 base 会打到 Dex 根路径 404），统一补全。"""
	url = (os.getenv("DH_TOKEN_URL") or "http://127.0.0.1:6062").rstrip("/")
	return url if url.endswith("/auth/token") else url + "/auth/token"


def make_client() -> AppMeshClient:
	token = os.getenv("APPMESH_BEARER_TOKEN")
	if token:
		return AppMeshClient(
			base_url=os.getenv("APPMESH_URL", "https://127.0.0.1:6060"),
			ssl_verify=os.getenv("APPMESH_CA") or None,
			bearer_token=token,
		)
	password_file, username = _discover_password_file()
	if password_file:
		try:
			provider = PasswordGrantProvider(
				token_url=_token_url(),
				username=os.getenv("DH_BOT_USER", username),
				password_file=password_file,
			)
		except ValueError as exc:  # SDK 拒绝空密码文件 / 非 HTTPS 的远端 token URL
			raise RuntimeError(f"凭据不可用: {exc}") from exc
		return AppMeshClient(
			base_url=os.getenv("APPMESH_URL", "https://127.0.0.1:6060"),
			ssl_verify=os.getenv("APPMESH_CA") or None,
			token_provider=provider,
		)
	raise RuntimeError("缺少凭据 — 设置 APPMESH_BEARER_TOKEN，或 DH_BOT_PASSWORD_FILE(+DH_BOT_USER/DH_TOKEN_URL)；重跑 setup.sh 可重新生成")


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
