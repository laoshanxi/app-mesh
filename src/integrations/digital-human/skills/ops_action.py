"""ops-action 技能：高危操作示例（P1-4）—— 演示"未审批不执行"的闸门模式。

- 低危动作（status-check）直接执行（mock）；
- 高危动作（restart-service）第一次调用只登记审批并返回 approval_id，
  审批通过后携带 approval_id 重试才真正执行（mock 执行：写执行日志）。

入参:
  {"action": "status-check", "service": "nginx"}
  {"action": "restart-service", "service": "nginx", "requester": "zhangsan", "approval_id": "AP-xxxx"(可选)}
"""

import time
from pathlib import Path

import approval
from common import serve

_EXEC_LOG = Path(__file__).resolve().parent.parent / "runtime" / "ops-exec.log"


def _log(line):
	_EXEC_LOG.parent.mkdir(parents=True, exist_ok=True)
	with _EXEC_LOG.open("a", encoding="utf-8") as fh:
		fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")


def handler(request):
	action = request.get("action")
	service = str(request.get("service", "")).strip()
	if not service:
		return {"status": "error", "message": "'service' is required"}

	if action == "status-check":
		_log(f"status-check {service}")
		return {"status": "ok", "data": {"service": service, "state": "running", "note": "mock status"}}

	if action == "restart-service":
		approval_id = request.get("approval_id")
		if not approval_id:
			record = approval.create(
				f"重启服务 {service}",
				str(request.get("requester", "unknown")),
				"high",
				{"action": "restart-service", "service": service},
			)
			return {
				"status": "approval_required",
				"approval_id": record["id"],
				"message": f"高危操作已登记审批 {record['id']}，等待审批通过后携带 approval_id 重试",
			}
		record = approval.get(str(approval_id))
		if record is None:
			return {"status": "error", "message": f"no such approval: {approval_id}"}
		if record.get("payload", {}).get("service") != service:
			return {"status": "error", "message": "approval 与操作不匹配"}
		if record["status"] != "approved":
			return {"status": "approval_required", "approval_id": record["id"], "message": f"审批当前状态: {record['status']}"}
		if record.get("consumed"):
			return {"status": "error", "message": "该审批已被使用，请重新发起"}
		# mock 执行
		_log(f"RESTART {service} approved_by={record.get('decided_by')} approval={record['id']}")
		approval.mark_consumed(str(approval_id))
		return {"status": "ok", "data": {"service": service, "restarted": True, "approval": record["id"], "note": "mock restart"}}

	return {"status": "error", "message": f"unknown action: {action}"}


if __name__ == "__main__":
	serve(handler)
