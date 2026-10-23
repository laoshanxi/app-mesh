"""ops-action 技能：高危操作示例（P1-4）—— 演示"未审批不执行"的闸门模式。

- 低危动作（status-check）直接执行（mock）；
- 高危动作（restart-service）第一次调用只登记审批并返回 approval_id，
  审批通过后携带 approval_id 重试才真正执行（mock 执行：写执行日志）。
- 校验与"标记已消费"在 approval.consume() 的文件锁内原子完成：同一审批
  只能执行一次，且 payload 必须与登记时完全一致（防挪用）。

入参:
  {"action": "status-check", "service": "nginx"}
  {"action": "restart-service", "service": "nginx", "requester": "zhangsan", "approval_id": "AP-xxxx"(可选)}
"""

import os
import time
from pathlib import Path

import approval
from common import serve

_EXEC_LOG = Path(__file__).resolve().parent.parent / "runtime" / "ops-exec.log"


def _log(line):
	_EXEC_LOG.parent.mkdir(parents=True, exist_ok=True)
	with _EXEC_LOG.open("a", encoding="utf-8") as fh:
		fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")
	os.chmod(_EXEC_LOG, 0o600)


def handler(request):
	action = request.get("action")
	service = str(request.get("service", "")).strip()
	if not service:
		return {"status": "error", "message": "'service' is required"}

	if action == "status-check":
		_log(f"status-check {service}")
		return {"status": "ok", "data": {"service": service, "state": "running", "note": "mock status"}}

	if action == "restart-service":
		payload = {"action": "restart-service", "service": service}
		approval_id = request.get("approval_id")
		if not approval_id:
			record = approval.create(f"重启服务 {service}", str(request.get("requester", "unknown")), "high", payload)
			return {
				"status": "approval_required",
				"approval_id": record["id"],
				"message": f"高危操作已登记审批 {record['id']}，等待审批通过后携带 approval_id 重试",
			}
		result = approval.consume(str(approval_id), payload)
		if result["status"] != "ok":
			return result
		record = result["approval"]
		# mock 执行（审批已在锁内标记为已消费，先到者得）
		_log(f"RESTART {service} approved_by={record.get('decided_by')} approval={record['id']}")
		return {"status": "ok", "data": {"service": service, "restarted": True, "approval": record["id"], "note": "mock restart"}}

	return {"status": "error", "message": f"unknown action: {action}"}


if __name__ == "__main__":
	serve(handler)
