"""jira-query 技能：工单查询 connector（业务系统打通的原型）。

Phase 0: 用本地 mock 数据演示契约；接入真实环境时只需替换 _fetch_issues()
为 Jira REST 调用，入参出参不变。

入参:
  {"action": "search", "assignee": "zhangsan", "status": "open"}
  {"action": "get", "key": "OPS-101"}
"""

import json
import os
from pathlib import Path

from common import serve

_DEFAULT_MOCK = Path(__file__).resolve().parent.parent / "data" / "mock" / "jira.json"
_MOCK = Path(os.getenv("JIRA_MOCK_FILE", str(_DEFAULT_MOCK)))


def _fetch_issues():
	# TODO(Phase 1): 换成真实 Jira REST 调用（服务账号 token + requests）
	return json.loads(_MOCK.read_text(encoding="utf-8"))["issues"]


def handler(request):
	action = request.get("action", "search")
	issues = _fetch_issues()
	if action == "get":
		key = str(request.get("key", ""))
		for issue in issues:
			if issue["key"] == key:
				return {"status": "ok", "issue": issue}
		return {"status": "error", "message": f"no such issue: {key}"}
	if action == "search":
		assignee = request.get("assignee")
		status = request.get("status")
		matched = [
			i
			for i in issues
			if (not assignee or i["assignee"] == assignee) and (not status or i["status"] == status)
		]
		return {"status": "ok", "count": len(matched), "issues": matched}
	return {"status": "error", "message": f"unknown action: {action}"}


if __name__ == "__main__":
	serve(handler)
