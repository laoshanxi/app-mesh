"""技能 handler 边界回归（2026-10 第二轮审计修复）。"""

import json

import jira_query
import kb_search
import sys_info


def test_kb_top_k_invalid_is_friendly_error(tmp_path, monkeypatch):
	monkeypatch.setattr(kb_search, "_KB_DIR", tmp_path)
	monkeypatch.setattr(kb_search, "_CACHE", {"mtime": None, "docs": [], "df": {}})
	(tmp_path / "a.md").write_text("# 标题\n报销制度正文", encoding="utf-8")
	r = kb_search.handler({"query": "报销", "top_k": "abc"})
	assert r["status"] == "error"
	assert r["message"] == "'top_k' must be an integer"


def test_kb_top_k_clamped(tmp_path, monkeypatch):
	monkeypatch.setattr(kb_search, "_KB_DIR", tmp_path)
	monkeypatch.setattr(kb_search, "_CACHE", {"mtime": None, "docs": [], "df": {}})
	(tmp_path / "a.md").write_text("# 报销制度\n正文", encoding="utf-8")
	assert len(kb_search.handler({"query": "报销", "top_k": -5})["results"]) == 0  # 负数收敛为 0
	assert len(kb_search.handler({"query": "报销", "top_k": 999})["results"]) == 1  # 上限 50，按文档数截断


def test_kb_empty_dir_no_crash(tmp_path, monkeypatch):
	monkeypatch.setattr(kb_search, "_KB_DIR", tmp_path)
	monkeypatch.setattr(kb_search, "_CACHE", {"mtime": None, "docs": [], "df": {}})
	assert kb_search.handler({"query": "x"})["results"] == []


def test_jira_tolerates_missing_fields(tmp_path, monkeypatch):
	data = tmp_path / "jira.json"
	data.write_text(json.dumps({"issues": [{"key": "OPS-1", "title": "t"}]}), encoding="utf-8")  # 无 assignee/status
	monkeypatch.setattr(jira_query, "_MOCK", data)
	r = jira_query.handler({"action": "search"})  # 不带过滤条件
	assert r["status"] == "ok" and r["count"] == 1
	r = jira_query.handler({"action": "search", "assignee": "zhangsan"})
	assert r["status"] == "ok" and r["count"] == 0  # 缺字段按不匹配处理，不再 KeyError
	assert jira_query.handler({"action": "get", "key": "OPS-1"})["status"] == "ok"


def test_sys_info_ok():
	r = sys_info.handler({})
	assert r["status"] == "ok"
	assert r["data"]["memory_gb"] >= 0  # sysconf 不可用时为 0 而非抛异常
