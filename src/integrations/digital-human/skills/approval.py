"""审批登记薄：SQLite 存储，oa-approval 与 ops-action 共用（P1-4）。

Phase 1 的确认动作是 mock（CLI/chat 调 oa-approval approve 即视为"IM 点了同意"），
Phase 1+ 接真实 IM 回调时替换 decide() 的入口即可，存储不变。

为什么是 SQLite 而不是手锁 JSON 文件：两个技能 App 是独立进程共写一份数据，
SQLite 的单语句原子性 + busy_timeout 天然提供跨进程互斥，"校验 + 更新"
合并为一条条件 UPDATE 即无竞态。此前 JSON+flock 方案的锁文件、临时文件与
重命名约定全部不再需要。

安全规则（2026-10 对抗审计修复）:
- 审批人不得是申请人本人：decide() 拒绝自审批（mock 阶段 `by` 为自报身份，
  接真实 IM 后应换成认证主体）；
- payload 只能由执行方（ops-action）在登记时写入，oa-approval 不接受外部 payload，
  防止伪造与任意操作绑定的审批单；
- consume() 用条件 UPDATE 原子完成"校验 + 标记已消费"，同一审批只能执行一次；
- 数据库文件权限 0600。
"""

import json
import os
import shutil
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path

try:
	import fcntl
except ImportError:  # 非 POSIX 平台退化为进程内锁（部署目标为 macOS/Linux）
	fcntl = None

_DEFAULT_FILE = Path(__file__).resolve().parent.parent / "runtime" / "approvals.db"
_FILE = Path(os.getenv("APPROVAL_FILE", str(_DEFAULT_FILE)))

_COLS = "id, title, requester, risk, status, created, payload, decided_by, consumed"
_CREATE_SQL = (
	"CREATE TABLE IF NOT EXISTS approvals ("
	"id TEXT PRIMARY KEY, title TEXT, requester TEXT, risk TEXT, "
	"status TEXT, created TEXT, payload TEXT, decided_by TEXT, consumed INTEGER NOT NULL DEFAULT 0)"
)


_ensure_lock = threading.Lock()


def _ensure_file():
	"""库文件存在且 0600。创建用 O_EXCL：跨进程先到者得，后到者收到
	FileExistsError 直接复用。仅在调用方持有 _ensure_lock 时安全。"""
	if not _FILE.exists():
		try:
			os.close(os.open(_FILE, os.O_CREAT | os.O_EXCL, 0o600))
		except FileExistsError:
			pass
	if os.stat(_FILE).st_mode & 0o777 != 0o600:
		os.chmod(_FILE, 0o600)


def _migrate_legacy_json():
	"""2026-10 之前的 JSON 台账一次性迁移为 SQLite（原文件保留为 *.legacy）。

	仅当文件非空、非 SQLite 魔数、且能解析为 JSON 时才迁移——刚由
	_ensure_file 创建的 0 字节新库不能被误判。跨进程用一次性 flock 互斥。
	仅在调用方持有 _ensure_lock 时安全。
	"""
	try:
		size = _FILE.stat().st_size
	except FileNotFoundError:
		return
	if size == 0:
		return
	with _FILE.open("rb") as fh:
		if fh.read(16).startswith(b"SQLite format 3"):
			return
	try:
		records = json.loads(_FILE.read_text(encoding="utf-8"))
	except (ValueError, OSError):
		return
	if not isinstance(records, dict):
		return
	mlock = _FILE.with_name(_FILE.name + ".mlock")
	mfd = os.open(mlock, os.O_RDWR | os.O_CREAT, 0o600)
	try:
		if fcntl is not None:
			fcntl.flock(mfd, fcntl.LOCK_EX)
		with _FILE.open("rb") as fh:  # 拿到锁后复核：别的进程可能已迁完
			if fh.read(16).startswith(b"SQLite format 3"):
				return
		# 先建好库、最后换入：换入前崩溃，JSON 原件仍在原位，下次重迁。
		tmp = _FILE.with_name(_FILE.name + ".migrating")
		tmp.unlink(missing_ok=True)
		conn = sqlite3.connect(tmp, timeout=10)
		os.chmod(tmp, 0o600)
		try:
			with conn:
				conn.execute(_CREATE_SQL)
				for r in records.values():
					conn.execute(
						f"INSERT OR IGNORE INTO approvals ({_COLS}) VALUES (?,?,?,?,?,?,?,?,?)",
						(r.get("id"), r.get("title"), r.get("requester"), r.get("risk"), r.get("status"),
						 r.get("created"), json.dumps(r.get("payload") or {}, ensure_ascii=False),
						 r.get("decided_by"), int(bool(r.get("consumed")))),
					)
		finally:
			conn.close()
		shutil.copy2(_FILE, _FILE.with_name(_FILE.name + ".legacy"))
		os.replace(tmp, _FILE)
	finally:
		os.close(mfd)
		mlock.unlink(missing_ok=True)


def _quarantine_corrupt(exc):
	"""损坏的库文件挪到 *.corrupt-<ts> 留作取证，服务以空账本继续。"""
	target = _FILE.with_name(f"{_FILE.name}.corrupt-{int(time.time())}")
	os.replace(_FILE, target)
	for suffix in ("-journal", "-wal", "-shm"):  # 旁车属于旧库，残留会被 SQLite 当热日志回放进新空库
		_FILE.with_name(_FILE.name + suffix).unlink(missing_ok=True)
	print(f"[approval] 账本不是合法的 SQLite 文件（{exc}），已隔离到 {target} 并重建空账本", file=sys.stderr, flush=True)


def _connect():
	_FILE.parent.mkdir(parents=True, exist_ok=True)
	with _ensure_lock:
		_ensure_file()
		_migrate_legacy_json()
		conn = sqlite3.connect(_FILE, timeout=10)
		try:
			conn.execute("PRAGMA busy_timeout=10000")
			conn.execute(_CREATE_SQL)
		except sqlite3.DatabaseError as exc:
			conn.close()
			# 只处理"不是数据库/已损坏"；加锁超时等 OperationalError 原样抛出。
			msg = str(exc)
			if isinstance(exc, sqlite3.OperationalError) or not ("not a database" in msg or "malformed" in msg):
				raise
			_quarantine_corrupt(exc)
			_ensure_file()
			conn = sqlite3.connect(_FILE, timeout=10)
			conn.execute("PRAGMA busy_timeout=10000")
			conn.execute(_CREATE_SQL)
	return conn


def _row_to_record(row):
	rec = dict(zip(_COLS.split(", "), row))
	rec["payload"] = json.loads(rec["payload"] or "{}")
	rec["consumed"] = bool(rec["consumed"])
	return rec


def create(title, requester, risk, payload=None):
	approval_id = "AP-" + uuid.uuid4().hex[:8]
	conn = _connect()
	try:
		with conn:
			conn.execute(
				f"INSERT INTO approvals ({_COLS}) VALUES (?,?,?,?,?,?,?,?,?)",
				(approval_id, title, requester, risk, "pending", time.strftime("%Y-%m-%d %H:%M:%S"),
				 json.dumps(payload or {}, ensure_ascii=False), None, 0),
			)
	finally:
		conn.close()
	return {"id": approval_id, "title": title, "requester": requester, "risk": risk, "status": "pending",
			"created": time.strftime("%Y-%m-%d %H:%M:%S"), "payload": payload or {}, "decided_by": None, "consumed": False}


def decide(approval_id, decision, by):
	"""decision: 'approved' | 'rejected'。审批人不能是申请人本人。"""
	by = (by or "").strip()
	conn = _connect()
	try:
		with conn:
			row = conn.execute(f"SELECT {_COLS} FROM approvals WHERE id=?", (approval_id,)).fetchone()
			if row is None:
				return {"status": "error", "message": f"no such approval: {approval_id}"}
			record = _row_to_record(row)
			if record["status"] != "pending":
				return {"status": "error", "message": f"already {record['status']}"}
			if decision not in ("approved", "rejected"):
				return {"status": "error", "message": "decision must be approved/rejected"}
			if not by or by == "unknown":
				return {"status": "error", "message": "审批人未知（by 不能为空/unknown）"}
			if by == record.get("requester"):
				return {"status": "error", "message": "审批人不能是申请人本人"}
			# 条件更新兜底并发：状态被别的进程改走则 rowcount=0
			cur = conn.execute("UPDATE approvals SET status=?, decided_by=? WHERE id=? AND status='pending'", (decision, by, approval_id))
			if cur.rowcount != 1:
				return {"status": "error", "message": "already decided"}
			record["status"], record["decided_by"] = decision, by
			return {"status": "ok", "approval": record}
	finally:
		conn.close()


def get(approval_id):
	conn = _connect()
	try:
		row = conn.execute(f"SELECT {_COLS} FROM approvals WHERE id=?", (approval_id,)).fetchone()
		return _row_to_record(row) if row else None
	finally:
		conn.close()


def consume(approval_id, expect_payload):
	"""原子完成"校验 + 标记已消费"，只允许执行方（ops-action）调用。

	expect_payload 必须与登记时写入的 payload 完全一致，防止审批被挪用到别的操作。
	"""
	expect = json.dumps(expect_payload or {}, ensure_ascii=False, sort_keys=True)
	conn = _connect()
	try:
		with conn:
			row = conn.execute(f"SELECT {_COLS} FROM approvals WHERE id=?", (approval_id,)).fetchone()
			if row is None:
				return {"status": "error", "message": f"no such approval: {approval_id}"}
			record = _row_to_record(row)
			if json.dumps(record["payload"], ensure_ascii=False, sort_keys=True) != expect:
				return {"status": "error", "message": "approval 与操作不匹配"}
			if record["status"] != "approved":
				return {"status": "approval_required", "approval_id": record["id"], "message": f"审批当前状态: {record['status']}"}
			# 条件更新即"先到者得"：并发下仅一个进程 rowcount=1
			cur = conn.execute("UPDATE approvals SET consumed=1 WHERE id=? AND status='approved' AND consumed=0", (approval_id,))
			if cur.rowcount != 1:
				return {"status": "error", "message": "该审批已被使用，请重新发起"}
			record["consumed"] = True
			return {"status": "ok", "approval": record}
	finally:
		conn.close()


def pending():
	conn = _connect()
	try:
		rows = conn.execute(f"SELECT {_COLS} FROM approvals WHERE status='pending'").fetchall()
		return [_row_to_record(r) for r in rows]
	finally:
		conn.close()


def all_records():
	conn = _connect()
	try:
		rows = conn.execute(f"SELECT {_COLS} FROM approvals").fetchall()
		return [_row_to_record(r) for r in rows]
	finally:
		conn.close()
