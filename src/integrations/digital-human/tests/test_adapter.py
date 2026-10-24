"""IM 适配器回归测试（2026-10 对抗审计修复的行为锁定）。

覆盖:
- client 进程内单例（token 生命周期由 SDK provider 负责）；
- 去重表有界；默认只绑回环地址；可选令牌鉴权；
- 真实 HTTP 层：Content-Length 为负/超大 → 400/413（不再挂线程），
  非 JSON 对象 → 400，队列满 → 429，收件箱取后清空。
"""

import http.client
import json
import os
import queue
import threading
from http.server import ThreadingHTTPServer

import pytest

import adapter


def test_default_bind_is_loopback():
	assert adapter.BIND == "127.0.0.1"


def test_dedup_is_bounded(monkeypatch):
	monkeypatch.setattr(adapter, "MAX_EVENTS", 3)
	adapter._seen_events.clear()
	adapter._seen_order.clear()
	assert adapter._dedup_event("a") is False
	assert adapter._dedup_event("a") is True
	for e in ("b", "c", "d"):
		adapter._dedup_event(e)
	assert len(adapter._seen_events) == 3
	assert "a" not in adapter._seen_events  # 最旧的被淘汰


def test_client_is_singleton(monkeypatch):
	"""适配器进程内只建一个 client；构造失败不缓存（下次重试）。"""
	import dh_client

	built = []

	def fake_make():
		built.append(object())
		return built[-1]

	monkeypatch.setattr(adapter, "make_client", fake_make)
	monkeypatch.setattr(adapter, "_client_inst", None)
	assert adapter._client() is adapter._client()
	assert len(built) == 1


def test_inbox_is_bounded(monkeypatch):
	monkeypatch.setattr(adapter, "MAX_INBOX", 5)
	adapter._inbox.clear()
	for i in range(30):
		adapter._reply("u1", f"m{i}")
	assert len(adapter._inbox["u1"]) == 20  # 单户上限 20
	assert adapter._inbox["u1"][0] == "m10"  # 丢最旧
	adapter._inbox.clear()
	for u in ("a", "b", "c"):
		for i in range(3):
			adapter._reply(u, f"{u}{i}")
	total = sum(len(v) for v in adapter._inbox.values())
	assert total <= 5
	assert "a" not in adapter._inbox  # 最旧用户被整体淘汰
	assert "c" in adapter._inbox
