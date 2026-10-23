"""审批闸门回归测试（2026-10 对抗审计修复的行为锁定）。

覆盖:
- 自审批被拒、审批人未知被拒；
- oa-approval create 忽略外部 payload（伪造绑定无效）；
- 闸门端到端：未审批不执行 / 服务不匹配不执行 / 只能执行一次；
- 并发：创建不丢失、同一审批并发消费只成功一次；
- 文件权限 0600。
"""

import stat
import threading

import approval
import oa_approval
import ops_action


def _isolated(tmp_path, monkeypatch):
	monkeypatch.setattr(approval, "_FILE", tmp_path / "approvals.json")
	monkeypatch.setattr(ops_action, "_EXEC_LOG", tmp_path / "ops-exec.log")


def test_self_approval_rejected(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	rec = approval.create("重启 nginx", "zhangsan", "high", {"action": "restart-service", "service": "nginx"})
	r = approval.decide(rec["id"], "approved", "zhangsan")
	assert r["status"] == "error"
	assert "本人" in r["message"]
	assert approval.get(rec["id"])["status"] == "pending"


def test_unknown_approver_rejected(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	rec = approval.create("t", "zhangsan", "high")
	for by in ("", "unknown", "  "):
		r = approval.decide(rec["id"], "approved", by)
		assert r["status"] == "error"


def test_other_approver_decides_once(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	rec = approval.create("t", "zhangsan", "high")
	assert approval.decide(rec["id"], "approved", "wangwu")["status"] == "ok"
	assert approval.decide(rec["id"], "rejected", "wangwu")["status"] == "error"  # already approved


def test_oa_create_ignores_caller_payload(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	r = oa_approval.handler(
		{"action": "create", "title": "x", "requester": "a", "risk": "low", "payload": {"action": "restart-service", "service": "nginx"}}
	)
	assert r["status"] == "ok"
	assert r["approval"]["payload"] == {}


def test_gate_blocks_forged_payload_approval(tmp_path, monkeypatch):
	"""经 oa-approval 伪造的审批（即使他人审批通过）不能用于执行任何操作。"""
	_isolated(tmp_path, monkeypatch)
	aid = oa_approval.handler({"action": "create", "title": "x", "requester": "a", "risk": "high", "payload": {"action": "restart-service", "service": "nginx"}})["approval"]["id"]
	assert oa_approval.handler({"action": "approve", "id": aid, "by": "boss"})["status"] == "ok"
	res = ops_action.handler({"action": "restart-service", "service": "nginx", "requester": "a", "approval_id": aid})
	assert res["status"] == "error"
	assert "不匹配" in res["message"]


def test_gate_end_to_end_single_use(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	# 登记审批
	r = ops_action.handler({"action": "restart-service", "service": "nginx", "requester": "zhangsan"})
	assert r["status"] == "approval_required"
	aid = r["approval_id"]
	# 申请人自审批被拒
	assert oa_approval.handler({"action": "approve", "id": aid, "by": "zhangsan"})["status"] == "error"
	# 未审批先执行被拒
	assert ops_action.handler({"action": "restart-service", "service": "nginx", "approval_id": aid})["status"] == "approval_required"
	# 审批人通过
	assert oa_approval.handler({"action": "approve", "id": aid, "by": "wangwu"})["status"] == "ok"
	# 服务不匹配被拒
	assert ops_action.handler({"action": "restart-service", "service": "mysql", "approval_id": aid})["status"] == "error"
	# 正确执行
	assert ops_action.handler({"action": "restart-service", "service": "nginx", "approval_id": aid})["status"] == "ok"
	# 第二次执行被拒
	again = ops_action.handler({"action": "restart-service", "service": "nginx", "approval_id": aid})
	assert again["status"] == "error"
	assert "已被使用" in again["message"]
	log = (tmp_path / "ops-exec.log").read_text(encoding="utf-8")
	assert log.count("RESTART nginx") == 1


def test_concurrent_creates_are_not_lost(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	threads = []
	for i in range(8):

		def work(i=i):
			for j in range(10):
				approval.create(f"t{i}-{j}", "u", "low")

		t = threading.Thread(target=work)
		t.start()
		threads.append(t)
	for t in threads:
		t.join()
	assert len(approval.all_records()) == 80


def test_concurrent_consume_wins_once(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	rec = approval.create("t", "zs", "high", {"action": "restart-service", "service": "nginx"})
	approval.decide(rec["id"], "approved", "boss")
	barrier = threading.Barrier(8)
	results = []
	lock = threading.Lock()

	def work():
		barrier.wait()
		r = approval.consume(rec["id"], {"action": "restart-service", "service": "nginx"})
		with lock:
			results.append(r["status"])

	threads = [threading.Thread(target=work) for _ in range(8)]
	for t in threads:
		t.start()
	for t in threads:
		t.join()
	assert results.count("ok") == 1
	assert set(results) == {"ok", "error"}


def test_store_files_are_0600(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	rec = approval.create("t", "zs", "high")
	assert stat.S_IMODE((tmp_path / "approvals.json").stat().st_mode) == 0o600
	assert stat.S_IMODE((tmp_path / "approvals.lock").stat().st_mode) == 0o600
