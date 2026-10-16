"""审批登记薄：JSON 文件存储，oa-approval 与 ops-action 共用（P1-4）。

Phase 1 的确认动作是 mock（CLI/chat 调 oa-approval approve 即视为"IM 点了同意"），
Phase 1+ 接真实 IM 回调时替换 decide() 的入口即可，存储不变。
"""

import json
import os
import time
import uuid
from pathlib import Path

_DEFAULT_FILE = Path(__file__).resolve().parent.parent / "runtime" / "approvals.json"
_FILE = Path(os.getenv("APPROVAL_FILE", str(_DEFAULT_FILE)))


def _load():
	if not _FILE.exists():
		return {}
	try:
		return json.loads(_FILE.read_text(encoding="utf-8"))
	except (ValueError, OSError):
		return {}


def _save(records):
	_FILE.parent.mkdir(parents=True, exist_ok=True)
	tmp = _FILE.with_suffix(".tmp")
	tmp.write_text(json.dumps(records, ensure_ascii=False, indent=1), encoding="utf-8")
	tmp.replace(_FILE)


def create(title, requester, risk, payload):
	records = _load()
	approval_id = "AP-" + uuid.uuid4().hex[:8]
	records[approval_id] = {
		"id": approval_id,
		"title": title,
		"requester": requester,
		"risk": risk,
		"status": "pending",
		"created": time.strftime("%Y-%m-%d %H:%M:%S"),
		"payload": payload,
		"decided_by": None,
		"consumed": False,
	}
	_save(records)
	return records[approval_id]


def decide(approval_id, decision, by):
	"""decision: 'approved' | 'rejected'。"""
	records = _load()
	record = records.get(approval_id)
	if record is None:
		return {"status": "error", "message": f"no such approval: {approval_id}"}
	if record["status"] != "pending":
		return {"status": "error", "message": f"already {record['status']}"}
	if decision not in ("approved", "rejected"):
		return {"status": "error", "message": "decision must be approved/rejected"}
	record["status"] = decision
	record["decided_by"] = by
	_save(records)
	return {"status": "ok", "approval": record}


def get(approval_id):
	return _load().get(approval_id)


def mark_consumed(approval_id):
	records = _load()
	record = records.get(approval_id)
	if record is not None:
		record["consumed"] = True
		_save(records)


def pending():
	return [r for r in _load().values() if r["status"] == "pending"]


def all_records():
	return list(_load().values())
