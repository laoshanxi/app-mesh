"""审批登记薄：JSON 文件存储，oa-approval 与 ops-action 共用（P1-4）。

Phase 1 的确认动作是 mock（CLI/chat 调 oa-approval approve 即视为"IM 点了同意"），
Phase 1+ 接真实 IM 回调时替换 decide() 的入口即可，存储不变。

安全与并发规则（2026-10 对抗审计修复）:
- 审批人不得是申请人本人：decide() 拒绝自审批；
- payload 只能由执行方（ops-action）在登记时写入，oa-approval 不接受外部 payload，
  防止伪造与任意操作绑定的审批单；
- consume() 在文件锁内完成"校验 + 标记已消费"，同一审批只能被执行一次；
- 所有写入走 flock 排它锁 + 每次写入独立的临时文件，跨进程（oa-approval 与
  ops-action 是两个独立 App 进程）不丢更新；文件权限 0600。
"""

import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

try:
	import fcntl
except ImportError:  # 非 POSIX 平台退化为无锁（部署目标为 macOS/Linux）
	fcntl = None

_DEFAULT_FILE = Path(__file__).resolve().parent.parent / "runtime" / "approvals.json"
_FILE = Path(os.getenv("APPROVAL_FILE", str(_DEFAULT_FILE)))


@contextmanager
def _exclusive():
	"""跨进程排它锁；锁文件与数据文件同目录。"""
	lock = _FILE.with_suffix(".lock")
	lock.parent.mkdir(parents=True, exist_ok=True)
	fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
	try:
		os.fchmod(fd, 0o600)
		if fcntl is not None:
			fcntl.flock(fd, fcntl.LOCK_EX)
		yield
	finally:
		os.close(fd)  # 释放 flock


def _load():
	if not _FILE.exists():
		return {}
	try:
		return json.loads(_FILE.read_text(encoding="utf-8"))
	except (ValueError, OSError):
		return {}


def _save(records):
	_FILE.parent.mkdir(parents=True, exist_ok=True)
	# 每次写入用独立临时文件：并发写者不会互相覆盖对方的临时文件
	tmp = _FILE.with_name(f"{_FILE.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
	tmp.write_text(json.dumps(records, ensure_ascii=False, indent=1), encoding="utf-8")
	os.chmod(tmp, 0o600)
	tmp.replace(_FILE)


def create(title, requester, risk, payload=None):
	with _exclusive():
		records = _load()
		approval_id = "AP-" + uuid.uuid4().hex[:8]
		records[approval_id] = {
			"id": approval_id,
			"title": title,
			"requester": requester,
			"risk": risk,
			"status": "pending",
			"created": time.strftime("%Y-%m-%d %H:%M:%S"),
			"payload": payload or {},
			"decided_by": None,
			"consumed": False,
		}
		_save(records)
		return records[approval_id]


def decide(approval_id, decision, by):
	"""decision: 'approved' | 'rejected'。审批人不能是申请人本人。"""
	with _exclusive():
		records = _load()
		record = records.get(approval_id)
		if record is None:
			return {"status": "error", "message": f"no such approval: {approval_id}"}
		if record["status"] != "pending":
			return {"status": "error", "message": f"already {record['status']}"}
		if decision not in ("approved", "rejected"):
			return {"status": "error", "message": "decision must be approved/rejected"}
		by = (by or "").strip()
		if not by or by == "unknown":
			return {"status": "error", "message": "审批人未知（by 不能为空/unknown）"}
		if by == record.get("requester"):
			return {"status": "error", "message": "审批人不能是申请人本人"}
		record["status"] = decision
		record["decided_by"] = by
		_save(records)
		return {"status": "ok", "approval": record}


def get(approval_id):
	return _load().get(approval_id)


def consume(approval_id, expect_payload):
	"""锁内原子完成"校验 + 标记已消费"，只允许执行方（ops-action）调用。

	expect_payload 必须与登记时写入的 payload 完全一致，防止审批被挪用到别的操作。
	"""
	with _exclusive():
		records = _load()
		record = records.get(approval_id)
		if record is None:
			return {"status": "error", "message": f"no such approval: {approval_id}"}
		if record.get("payload") != expect_payload:
			return {"status": "error", "message": "approval 与操作不匹配"}
		if record["status"] != "approved":
			return {"status": "approval_required", "approval_id": record["id"], "message": f"审批当前状态: {record['status']}"}
		if record.get("consumed"):
			return {"status": "error", "message": "该审批已被使用，请重新发起"}
		record["consumed"] = True
		_save(records)
		return {"status": "ok", "approval": record}


def pending():
	return [r for r in _load().values() if r["status"] == "pending"]


def all_records():
	return list(_load().values())
