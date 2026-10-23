#!/usr/bin/env python3
"""数字人 IM 适配器（P1-1，mock 优先）。

职责: IM 消息 → 认出用户 → run_task(<team>-agent, session_send) → 答案推回 IM。
大脑单轮 30s~10min，所以 webhook 必须立即应答，答案异步投递。

Mock 模式（当前）:
  POST /webhook/mock      {"user": "zhangsan", "text": "..."}   → 202 入队
  GET  /mock/inbox/<user>                                       → {"messages": [...]}（取后清空）
飞书事件格式（真实链路的解析已就绪，回复仍走 mock 收件箱）:
  POST /webhook/feishu     url_verification 应答 challenge；im.message.receive_v1 事件
                           按 event_id 去重后入队。接真实回复时替换 _reply()。

注册: setup.sh 渲染 apps/im-adapter.yaml 后由 App Mesh 托管（keepalive + 健康检查）。

安全基线（2026-10 对抗审计修复）:
- 默认只监听 127.0.0.1（DH_IM_BIND 覆盖）；对外暴露必须配 DH_IM_TOKEN 鉴权；
- DH_IM_TOKEN 设置后，除 /healthz 外所有端点要求 Authorization: Bearer 或 X-IM-Token；
- 请求体上限 DH_IM_MAX_BODY（默认 1MB），Content-Length 非法/为负直接 400；
- 飞书 event_id 去重表有界（DH_IM_MAX_EVENTS，默认 1 万），长期运行不涨内存；
- 队列有界（DH_IM_MAX_QUEUE，默认 200），满了返回 429 而不是无限堆积；
- token 缓存在内存，收到 401 时经 DH_TOKEN_CMD 重铸后重试一次（Dex token 有 TTL）。
"""

import json
import os
import queue
import subprocess
import sys
import threading
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills"))

from dh_client import make_client, send_turn  # noqa: E402

TEAM = os.getenv("DH_TEAM", "demo")
BIND = os.getenv("DH_IM_BIND", "127.0.0.1")
PORT = int(os.getenv("DH_IM_PORT", "7070"))
AGENT_TIMEOUT = int(os.getenv("DH_AGENT_TIMEOUT", "580"))
IM_TOKEN = os.getenv("DH_IM_TOKEN", "")
MAX_BODY = int(os.getenv("DH_IM_MAX_BODY", str(1024 * 1024)))
MAX_QUEUE = int(os.getenv("DH_IM_MAX_QUEUE", "200"))
MAX_EVENTS = int(os.getenv("DH_IM_MAX_EVENTS", "10000"))
# 每个用户一个稳定 session_id（uuid5），跨消息延续同一对话与个人工作目录
_SESSION_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "digital-human:" + TEAM)

_jobs = queue.Queue(maxsize=MAX_QUEUE)
_inbox = {}
_inbox_lock = threading.Lock()
_seen_events = {}
_seen_order = deque()


def session_id_for(user):
	return str(uuid.uuid5(_SESSION_NS, user))


# ---- token：内存缓存 + 401 重铸（不能写进 os.environ 永久缓存，Dex token 会过期）----

_token_lock = threading.Lock()
_token = os.getenv("APPMESH_BEARER_TOKEN", "")


def _mint_token():
	"""执行 DH_TOKEN_CMD 铸新 token。"""
	cmd = os.environ.get("DH_TOKEN_CMD")
	if not cmd:
		raise RuntimeError("缺少 APPMESH_BEARER_TOKEN 且未配置 DH_TOKEN_CMD")
	out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, check=True).stdout.strip()
	if not out:
		raise RuntimeError("DH_TOKEN_CMD 未铸出 token")
	return out


def _get_token(force=False):
	global _token
	with _token_lock:
		if force or not _token:
			_token = _mint_token()
		return _token


def _is_auth_error(text):
	t = str(text).lower()
	return "401" in t or "unauthorized" in t


def _client():
	os.environ["APPMESH_BEARER_TOKEN"] = _get_token()
	return make_client()


def _send_turn(session_id, text):
	"""发一轮对话；认证失败时重铸 token 重试一次。"""
	for attempt in (0, 1):
		try:
			resp = send_turn(_client(), session_id, text, timeout=AGENT_TIMEOUT)
		except Exception as exc:
			if attempt == 0 and _is_auth_error(exc):
				_get_token(force=True)
				continue
			raise
		if attempt == 0 and isinstance(resp, dict) and _is_auth_error(json.dumps(resp, ensure_ascii=False)):
			_get_token(force=True)
			continue
		return resp


def _reply(user, text):
	"""把答案投回 IM。mock: 收件箱；接真实 IM 时这里换成 IM 的回复 API。"""
	with _inbox_lock:
		_inbox.setdefault(user, []).append(text)


def _dedup_event(event_id):
	"""记录 event_id，重复返回 True；容量有界，超出淘汰最旧。"""
	if event_id in _seen_events:
		return True
	_seen_events[event_id] = None
	_seen_order.append(event_id)
	while len(_seen_order) > MAX_EVENTS:
		_seen_events.pop(_seen_order.popleft(), None)
	return False


def _worker():
	while True:
		user, text = _jobs.get()
		try:
			resp = _send_turn(session_id_for(user), text)
			if resp.get("status") == "ok":
				answer = (resp.get("data") or {}).get("answer") or json.dumps(resp.get("data"), ensure_ascii=False)
				_reply(user, answer)
			else:
				_reply(user, f"[数字人出错] {json.dumps(resp, ensure_ascii=False)[:300]}")
		except Exception as exc:  # 队列线程不能挂
			_reply(user, f"[数字人出错] {exc}")


class Handler(BaseHTTPRequestHandler):
	def log_message(self, fmt, *args):
		print(f"[im] {self.client_address[0]} {fmt % args}", flush=True)

	def _json(self, code, body):
		data = json.dumps(body, ensure_ascii=False).encode("utf-8")
		self.send_response(code)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	def _authorized(self):
		if not IM_TOKEN:
			return True
		auth = self.headers.get("Authorization", "")
		return auth == f"Bearer {IM_TOKEN}" or self.headers.get("X-IM-Token") == IM_TOKEN

	def _enqueue(self, user, text, code=202):
		try:
			_jobs.put_nowait((user, text))
		except queue.Full:
			return self._json(429, {"error": "queue full, retry later"})
		return self._json(code, {"ok": True, "queued": _jobs.qsize(), "session": session_id_for(user)})

	def do_GET(self):
		if self.path == "/healthz":
			return self._json(200, {"ok": True, "team": TEAM})
		if not self._authorized():
			return self._json(401, {"error": "unauthorized"})
		if self.path.split("?", 1)[0].startswith("/mock/inbox/"):
			user = self.path.split("?", 1)[0].rsplit("/", 1)[-1] or "unknown"
			with _inbox_lock:
				messages = _inbox.pop(user, [])
			return self._json(200, {"user": user, "messages": messages})
		return self._json(404, {"error": "not found"})

	def do_POST(self):
		if not self._authorized():
			return self._json(401, {"error": "unauthorized"})
		try:
			length = int(self.headers.get("Content-Length") or 0)
		except ValueError:
			return self._json(400, {"error": "bad content-length"})
		if length < 0:
			return self._json(400, {"error": "bad content-length"})
		if length > MAX_BODY:
			return self._json(413, {"error": "body too large"})
		try:
			body = json.loads(self.rfile.read(length) if length else b"{}")
		except ValueError:
			return self._json(400, {"error": "bad json"})
		if not isinstance(body, dict):
			return self._json(400, {"error": "json object required"})
		if self.path == "/webhook/mock":
			user, text = str(body.get("user", "unknown")), str(body.get("text", "")).strip()
			if not text:
				return self._json(400, {"error": "empty text"})
			return self._enqueue(user, text)
		if self.path == "/webhook/feishu":
			return self._feishu(body)
		return self._json(404, {"error": "not found"})

	def _feishu(self, body):
		# URL 验证（飞书配置回调地址时的握手）
		if body.get("type") == "url_verification":
			return self._json(200, {"challenge": body.get("challenge", "")})
		header = body.get("header") or {}
		event_id = header.get("event_id")
		if event_id and _dedup_event(event_id):
			return self._json(200, {"ok": True, "dedup": True})
		if header.get("event_type") == "im.message.receive_v1":
			event = body.get("event") or {}
			message = event.get("message") or {}
			if message.get("message_type") == "text":
				try:
					text = json.loads(message.get("content") or "{}").get("text", "")
				except ValueError:
					text = ""
				sender = ((event.get("sender") or {}).get("sender_id") or {}).get("open_id") or "feishu-unknown"
				clean = text.replace("@_user_", " ") if text else ""
				if clean.strip():
					return self._enqueue(sender, clean.strip(), code=200)  # 飞书要求 200 应答
		return self._json(200, {"ok": True, "ignored": header.get("event_type", "?")})


def main():
	for _ in range(2):
		threading.Thread(target=_worker, daemon=True).start()
	server = ThreadingHTTPServer((BIND, PORT), Handler)
	print(f"[im] adapter ready: team={TEAM} bind={BIND}:{PORT} auth={'on' if IM_TOKEN else 'off'} (mock inbox: GET /mock/inbox/<user>)", flush=True)
	server.serve_forever()


if __name__ == "__main__":
	main()
