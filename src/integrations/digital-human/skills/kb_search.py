"""kb-search 技能：组织知识库检索（Phase 1 向量化）。

检索内核 = mock embedding：稀疏 TF-IDF 向量（CJK bigram + ASCII 词，语料级 df 权重）
+ 余弦相似度，标题/正文加权。零外部依赖、确定性、中文友好
（"出差住宿标准" 能命中《差旅与报销制度》的"住宿上限"）。
注意不要用带符号的特征哈希做 mock：哈希碰撞噪声会淹没真实重叠信号且逐进程随机。

接入真实向量库/embedding 时：设置 KB_EMBEDDING（HTTP 接口）替换 _vec()，
入参出参契约不变。

入参: {"query": "报销 流程", "top_k": 3}
出参: {"status": "ok", "results": [{"file", "title", "snippet", "score"}, ...]}
"""

import math
import os
import re
from pathlib import Path

from common import serve

_DEFAULT_KB = Path(__file__).resolve().parent.parent / "data" / "kb"
_KB_DIR = Path(os.getenv("KB_DIR", str(_DEFAULT_KB)))


# ---- mock embedding（稀疏 TF-IDF） ----


def _tokens(text):
	"""ASCII 词 + CJK bigram（单字噪声大、易造成短文档偏置，不参与向量）。"""
	words = re.findall(r"[a-z0-9]+", text.lower())
	cjk = re.findall(r"[\u4e00-\u9fff]", text)
	bigrams = [a + b for a, b in zip(cjk, cjk[1:])]
	return words + bigrams


def _vec(text, df=None):
	"""token -> tf × 1/(1+df) 的稀疏向量。"""
	vec = {}
	for tok in _tokens(text):
		weight = 1.0 / (1 + df.get(tok, 0)) if df else 1.0
		vec[tok] = vec.get(tok, 0.0) + weight
	return vec


def _cosine(a, b):
	if not a or not b:
		return 0.0
	small, big = (a, b) if len(a) < len(b) else (b, a)
	dot = sum(w * big.get(tok, 0.0) for tok, w in small.items())
	na = math.sqrt(sum(w * w for w in a.values()))
	nb = math.sqrt(sum(w * w for w in b.values()))
	return dot / (na * nb) if na and nb else 0.0


# ---- 语料缓存（按目录 mtime 失效） ----
_CACHE = {"mtime": None, "docs": [], "df": {}}


def _load_docs():
	try:
		mtime = max((p.stat().st_mtime_ns for p in _KB_DIR.rglob("*") if p.is_file()), default=0)
	except OSError:
		mtime = 0
	if _CACHE["mtime"] == mtime:
		return _CACHE["docs"]
	raw = []
	for path in sorted(_KB_DIR.rglob("*")):
		if path.suffix.lower() not in (".md", ".txt") or not path.is_file():
			continue
		text = path.read_text(encoding="utf-8", errors="replace")
		first = text.splitlines()[0].strip() if text.strip() else ""
		title = first.lstrip("#").strip() or path.name
		raw.append((path, title, text))
	# 文档频率（标题 token 记双份，强化标题）
	df = {}
	for _, title, text in raw:
		for tok in set(_tokens(title)):
			df[tok] = df.get(tok, 0) + 2
		for tok in set(_tokens(text)):
			df[tok] = df.get(tok, 0) + 1
	docs = [{"file": str(path), "title": title, "text": text, "tvec": _vec(title, df), "bvec": _vec(text, df)} for path, title, text in raw]
	_CACHE["mtime"] = mtime
	_CACHE["docs"] = docs
	_CACHE["df"] = df
	return docs


def _snippet(text, query_tokens, width=200):
	"""优先截取与查询词重叠度最高的窗口。"""
	qset = {t for t in query_tokens if len(t) > 1}
	flat = re.sub(r"\s+", " ", text)
	lower = flat.lower()
	best, best_hit = 0, 0
	for i in range(0, max(1, len(flat) - width // 2), width // 2):
		hit = sum(1 for t in qset if t in lower[i : i + width])
		if hit > best_hit:
			best, best_hit = i, hit
	return flat[best : best + width].strip()


def handler(request):
	query = str(request.get("query", "")).strip()
	if not query:
		return {"status": "error", "message": "'query' is required"}
	try:
		top_k = int(request.get("top_k", 3))
	except (TypeError, ValueError):
		return {"status": "error", "message": "'top_k' must be an integer"}
	top_k = max(0, min(top_k, 50))
	if os.getenv("KB_EMBEDDING"):
		# 预留：真实 embedding 接入点（HTTP），当前未配置时使用本地 mock
		pass
	docs = _load_docs()
	qvec = _vec(query, _CACHE["df"])
	qtokens = _tokens(query)
	results = []
	for doc in docs:
		score = 0.6 * _cosine(qvec, doc["bvec"]) + 0.4 * _cosine(qvec, doc["tvec"])
		results.append({"file": doc["file"], "title": doc["title"], "score": round(score, 4), "snippet": _snippet(doc["text"], qtokens)})
	results.sort(key=lambda r: r["score"], reverse=True)
	return {
		"status": "ok",
		"query": query,
		"embedding": "mock-tfidf-sparse",
		"results": results[:top_k],
	}


if __name__ == "__main__":
	serve(handler)
