"""审批闸门回归测试（2026-10 对抗审计修复的行为锁定）。

覆盖:
- 自审批被拒、审批人未知被拒；
- oa-approval create 忽略外部 payload（伪造绑定无效）；
- 闸门端到端：未审批不执行 / 服务不匹配不执行 / 只能执行一次；
- 并发：创建不丢失、同一审批并发消费只成功一次（SQLite 事务）；
- 旧 JSON 台账一次性迁移；数据库文件 0600。
"""

import stat
import threading

import approval
import oa_approval
import ops_action


def _isolated(tmp_path, monkeypatch):
	monkeypatch.setattr(approval, "_FILE", tmp_path / "approvals.db")
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


def test_db_file_is_0600(tmp_path, monkeypatch):
	_isolated(tmp_path, monkeypatch)
	rec = approval.create("t", "zs", "high")
	assert stat.S_IMODE((tmp_path / "approvals.db").stat().st_mode) == 0o600


def test_legacy_json_migrated_once(tmp_path, monkeypatch):
	"""2026-10 之前的 JSON 台账自动迁入 SQLite，原文件保留为 .legacy。"""
	import json as _json
	db = tmp_path / "approvals.db"
	db.write_text(_json.dumps({"AP-old0001": {"id": "AP-old0001", "title": "旧单", "requester": "zs",
		"risk": "high", "status": "approved", "created": "2026-10-01 00:00:00",
		"payload": {"action": "restart-service", "service": "nginx"}, "decided_by": "boss", "consumed": False}}),
		encoding="utf-8")
	monkeypatch.setattr(approval, "_FILE", db)
	approval.create("新单", "ls", "low")  # 触发迁移 + 新建
	rec = approval.get("AP-old0001")
	assert rec is not None and rec["title"] == "旧单" and rec["status"] == "approved"
	assert (tmp_path / "approvals.db.legacy").exists()
	assert approval.get("AP-old0001") is not None  # 二次打开不再迁移，数据仍在


def test_legacy_migration_survives_interrupted_run(tmp_path, monkeypatch):
	"""迁移半途被杀（残留 .migrating）不丢记录：原件仍在，重跑即成功。"""
	import json as _json
	db = tmp_path / "approvals.db"
	db.write_text(_json.dumps({"AP-old0002": {"id": "AP-old0002", "title": "待批", "requester": "zs",
		"risk": "high", "status": "pending", "created": "2026-10-01 00:00:00",
		"payload": {}, "decided_by": None, "consumed": False}}), encoding="utf-8")
	(tmp_path / "approvals.db.migrating").write_bytes(b"half-written database from a killed process")
	monkeypatch.setattr(approval, "_FILE", db)
	assert approval.get("AP-old0002")["status"] == "pending"
	assert (tmp_path / "approvals.db.legacy").exists()
	assert not (tmp_path / "approvals.db.migrating").exists()
	assert db.read_bytes().startswith(b"SQLite format 3")


def test_corrupt_db_is_quarantined_and_service_recovers(tmp_path, monkeypatch):
	"""损坏账本被隔离取证，服务以空账本继续。"""
	_isolated(tmp_path, monkeypatch)
	(tmp_path / "approvals.db").write_bytes(b"\x00garbage that is neither sqlite nor json")
	(tmp_path / "approvals.db-journal").write_bytes(b"stale hot journal from the old ledger")
	rec = approval.create("t", "zs", "low")
	assert approval.get(rec["id"])["status"] == "pending"
	quarantined = list(tmp_path.glob("approvals.db.corrupt-*"))
	assert len(quarantined) == 1
	assert quarantined[0].read_bytes().startswith(b"\x00garbage")
	assert not (tmp_path / "approvals.db-journal").exists()  # 旧库的旁车不回放进新空库
	assert stat.S_IMODE((tmp_path / "approvals.db").stat().st_mode) == 0o600
