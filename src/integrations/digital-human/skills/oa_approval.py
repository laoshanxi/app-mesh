"""oa-approval 技能：审批登记与确认（P1-4，mock OA）。

Phase 1 确认动作 = 调用本技能 approve（模拟 IM 点同意/拒绝）；Phase 1+ 由 IM 适配器
回调触发。存储见 approval.py。

入参:
  {"action": "create",  "title": "...", "requester": "...", "risk": "high"}
  {"action": "approve", "id": "AP-xxxx", "by": "wangwu"}     # 或 reject
  {"action": "status",  "id": "AP-xxxx"}
  {"action": "list", "pending_only": true}
"""

import approval
from common import serve


def handler(request):
	action = request.get("action", "list")
	if action == "create":
		title = str(request.get("title", "")).strip()
		if not title:
			return {"status": "error", "message": "'title' is required"}
		record = approval.create(title, str(request.get("requester", "unknown")), str(request.get("risk", "low")), dict(request.get("payload") or {}))
		return {"status": "ok", "approval": record}
	if action in ("approve", "reject"):
		result = approval.decide(str(request.get("id", "")), "approved" if action == "approve" else "rejected", str(request.get("by", "unknown")))
		return result
	if action == "status":
		record = approval.get(str(request.get("id", "")))
		if record is None:
			return {"status": "error", "message": "no such approval"}
		return {"status": "ok", "approval": record}
	if action == "list":
		records = approval.pending() if request.get("pending_only") else approval.all_records()
		records.sort(key=lambda r: r.get("created", ""), reverse=True)
		return {"status": "ok", "count": len(records), "approvals": records}
	return {"status": "error", "message": f"unknown action: {action}"}


if __name__ == "__main__":
	serve(handler)
