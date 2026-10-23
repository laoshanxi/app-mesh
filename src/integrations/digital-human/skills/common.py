"""数字人技能 connector 公共骨架。

一个技能 = 一个常驻 App Mesh App，进程内跑 fetch_task 循环：
收到 JSON 载荷 -> 交给 handler(dict) -> 把返回的 dict 作为 JSON 结果送回调用方。
坏请求只报错，不能弄挂常驻进程。
"""

import json
import logging
import os

from appmesh import AppMeshWorkerTCP


def _tcp_address():
	raw = os.getenv("APPMESH_TCP", "127.0.0.1:6059")
	host, _, port = raw.rpartition(":")
	return (host or "127.0.0.1", int(port))


def serve(handler):
	"""阻塞式任务循环，handler 签名: (dict) -> dict。

	任务通道走 TCP API：fetch_task 需要托管进程证明，TCP worker 原生携带；
	HTTP worker 在部分 daemon 版本上会被 403 "managed process proof" 拒绝。
	"""
	logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
	log = logging.getLogger(os.getenv("APP_MESH_APPLICATION_NAME", "skill"))
	worker = AppMeshWorkerTCP(
		ssl_verify=os.getenv("APPMESH_CA") or None,
		tcp_address=_tcp_address(),
	)
	log.info("skill ready, waiting for tasks")
	while True:
		payload = worker.fetch_task()
		try:
			text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
			text = text.strip()
			request = json.loads(text) if text.startswith(("{", "[")) else {"input": text}
			response = handler(request)
			if not isinstance(response, dict):
				raise ValueError(f"handler must return dict, got {type(response).__name__}")
		except Exception as exc:  # 单次坏请求不能弄挂常驻服务
			log.exception("task failed")
			response = {"status": "error", "message": str(exc)}
		try:
			worker.send_task_result(json.dumps(response, ensure_ascii=False))
		except Exception:
			# 调用方已超时退出（daemon 回 417）时送结果会失败；只记日志，服务必须继续
			log.exception("send_task_result failed (caller gone?)")
