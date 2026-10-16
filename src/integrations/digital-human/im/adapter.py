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
"""

import json
import os
import queue
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills"))

from dh_client import make_client, send_turn  # noqa: E402

TEAM = os.getenv("DH_TEAM", "demo")
PORT = int(os.getenv("DH_IM_PORT", "7070"))
AGENT_TIMEOUT = int(os.getenv("DH_AGENT_TIMEOUT", "580"))
# 每个用户一个稳定 session_id（uuid5），跨消息延续同一对话与个人工作目录
_SESSION_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "digital-human:" + TEAM)

_jobs = queue.Queue()
_inbox = {}
_inbox_lock = threading.Lock()
_seen_events = set()


def session_id_for(user):
	return str(uuid.uuid5(_SESSION_NS, user))


def _client():
	"""按需铸 token：环境有则直接用，否则执行 DH_TOKEN_CMD（结果缓存进环境变量）。"""
	if not os.getenv("APPMESH_BEARER_TOKEN") and os.getenv("DH_TOKEN_CMD"):
		os.environ["APPMESH_BEARER_TOKEN"] = subprocess.run(
			["bash", "-c", os.environ["DH_TOKEN_CMD"]], capture_output=True, text=True, check=True
		).stdout.strip()
	return make_client()


def _reply(user, text):
	"""把答案投回 IM。mock: 收件箱；接真实 IM 时这里换成 IM 的回复 API。"""
	with _inbox_lock:
		_inbox.setdefault(user, []).append(text)


def _worker():
	while True:
		user, text = _jobs.get()
		try:
			resp = send_turn(_client(), session_id_for(user), text, timeout=AGENT_TIMEOUT)
			if resp.get("status") == "ok":
				answer = (resp.get("data") or {}).get("answer") or json.dumps(resp.get("data"), ensure_ascii=False)
				_reply(user, answer)
			else:
				_reply(user, f"[数字人出错] {json.dumps(resp, ensure_ascii=False)[:300]}")
		except Exception as exc:  # 队列线程不能挂
			_reply(user, f"[数字人出错] {exc}")


class Handler(BaseHTTPRequestHandler):
	def log_message(self, fmt, *args):
		print(f"[im] {self.address_string()} {fmt % args}", flush=True)

	def _json(self, code, body):
		data = json.dumps(body, ensure_ascii=False).encode("utf-8")
		self.send_response(code)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	def do_GET(self):
		if self.path == "/healthz":
			return self._json(200, {"ok": True, "team": TEAM})
		if self.path.startswith("/mock/inbox/"):
			user = self.path.rsplit("/", 1)[-1] or "unknown"
			with _inbox_lock:
				messages = _inbox.pop(user, [])
			return self._json(200, {"user": user, "messages": messages})
		return self._json(404, {"error": "not found"})

	def do_POST(self):
		length = int(self.headers.get("Content-Length") or 0)
		try:
			body = json.loads(self.rfile.read(length) or b"{}")
		except ValueError:
			return self._json(400, {"error": "bad json"})
		if self.path == "/webhook/mock":
			user, text = str(body.get("user", "unknown")), str(body.get("text", "")).strip()
			if not text:
				return self._json(400, {"error": "empty text"})
			_jobs.put((user, text))
			return self._json(202, {"ok": True, "queued": _jobs.qsize(), "session": session_id_for(user)})
		if self.path == "/webhook/feishu":
			return self._feishu(body)
		return self._json(404, {"error": "not found"})

	def _feishu(self, body):
		# URL 验证（飞书配置回调地址时的握手）
		if body.get("type") == "url_verification":
			return self._json(200, {"challenge": body.get("challenge", "")})
		header = body.get("header") or {}
		event_id = header.get("event_id")
		if event_id:
			if event_id in _seen_events:
				return self._json(200, {"ok": True, "dedup": True})
			_seen_events.add(event_id)
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
					_jobs.put((sender, clean.strip()))
					return self._json(200, {"ok": True})
		return self._json(200, {"ok": True, "ignored": header.get("event_type", "?")})


def main():
	for _ in range(2):
		threading.Thread(target=_worker, daemon=True).start()
	server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
	print(f"[im] adapter ready: team={TEAM} port={PORT} (mock inbox: GET /mock/inbox/<user>)", flush=True)
	server.serve_forever()


if __name__ == "__main__":
	main()
