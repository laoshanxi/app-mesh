#!/usr/bin/env bash
# 数字人 team 自建部署脚本（R4）—— 为一个 team 生成并注册全套 App。
#
# 用法:
#   bash setup.sh --team demo
#   bash setup.sh --team sre --kb-dir /data/sre-kb          # 指定团队自己的知识库目录
#   bash setup.sh --team demo --no-agent                    # 只部署技能，不部署大脑
#
# 可用环境变量覆盖默认值:
#   APPMESH_URL / APPMESH_WSS / APPMESH_CA / APPMESH_BEARER_TOKEN  连接与部署引导
#   DH_TOKEN_URL / DH_BOT_USER     运行时 provider 的认证端点与账号
#   DH_ADMIN_PASSWORD              dh-bot 不可用时的管理员回退（写入 600 密码文件）
#   DH_PYTHON      建 venv 用的 Python（需 >=3.10，默认 python3.14）
set -euo pipefail

TEAM="" KB_DIR="" NO_AGENT=0
while [ $# -gt 0 ]; do
	case "$1" in
	--team) TEAM="${2:?}"; shift 2 ;;
	--kb-dir) KB_DIR="${2:?}"; shift 2 ;;
	--no-agent) NO_AGENT=1; shift ;;
	*) echo "unknown option: $1" >&2; exit 1 ;;
	esac
done
[ -n "$TEAM" ] || { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[[ "$TEAM" =~ ^[a-z][a-z0-9-]{0,30}$ ]] || { echo "error: team 名只允许小写字母/数字/连字符: $TEAM" >&2; exit 1; }

PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PKG/../../.." && pwd)"
LLM_DIR="$REPO_ROOT/src/apps/llm-agent"
[ -d "$LLM_DIR/llm_agent" ] || { echo "error: 找不到 llm-agent 包: $LLM_DIR" >&2; exit 1; }

RUNTIME="$PKG/runtime"
TEAM_RT="$RUNTIME/$TEAM"
KB_DIR="${KB_DIR:-$PKG/data/kb}"
[ -d "$KB_DIR" ] || { echo "error: 知识库目录不存在: $KB_DIR" >&2; exit 1; }

APPMESH_URL="${APPMESH_URL:-https://127.0.0.1:6060}"
APPMESH_WSS="${APPMESH_WSS:-wss://127.0.0.1:6058}"
APPMESH_CA="${APPMESH_CA:-/opt/appmesh/ssl/ca.pem}"
TOKEN_URL="${DH_TOKEN_URL:-http://127.0.0.1:6062}"
IM_PORT="${DH_IM_PORT:-7070}"
# IM 适配器默认只听本机回环；对外暴露必须同时配 DH_IM_TOKEN（适配器端点鉴权）
IM_BIND="${DH_IM_BIND:-127.0.0.1}"
IM_TOKEN="${DH_IM_TOKEN:-}"
TCP_API="${DH_TCP_API:-127.0.0.1:6059}"
if [ -z "${APPMESH_BEARER_TOKEN:-}" ]; then
	# 部署引导 token：仅本脚本内的 API 调用使用（root 安装需 sudo 才能铸出）；
	# 运行时凭据见下方 provider 密码文件，不走这里
	APPMESH_BEARER_TOKEN="$(bash /opt/appmesh/script/appmesh-auth.sh print-initial-password 2>/dev/null | bash /opt/appmesh/script/appmesh-auth.sh user-token 2>/dev/null || true)"
	export APPMESH_BEARER_TOKEN
fi
if [ -z "${APPMESH_BEARER_TOKEN:-}" ]; then
	echo "error: 无法取得管理员 token — root 安装时标准流程需要 sudo（见 /opt/appmesh/NEXT_STEPS.txt）。" >&2
	echo "       请先 export APPMESH_BEARER_TOKEN=<有效管理员 token> 再运行本脚本。" >&2
	exit 1
fi

# ---- P1-3: 专用最小权限 principal（幂等；失败回退管理员密码文件）----
# 运行时凭据 = SDK PasswordGrantProvider + 600 权限密码文件（每次授予时重读，
# 密码轮换免重启；铸造/过期前刷新/401 重认证全部由 SDK 处理）。
AUTH_SCRIPT="${DH_AUTH_SCRIPT:-/opt/appmesh/script/appmesh-auth.sh}"
mkdir -p "$TEAM_RT"
BOT_ENV="$TEAM_RT/dh-bot.env"
if [ ! -f "$BOT_ENV" ]; then
	BOT_PW="dhbot-$(openssl rand -hex 8 2>/dev/null || date +%s)"
	_sq() { printf "%s" "$1" | sed "s/'/'\\\\''/g"; } # 值统一单引号包裹，防特殊字符破坏 source
	printf "DH_BOT_USER='%s'\nDH_BOT_PASSWORD='%s'\n" "$(_sq "${DH_BOT_USER:-dh-bot@$TEAM.local}")" "$(_sq "$BOT_PW")" > "$BOT_ENV"
	chmod 600 "$BOT_ENV"
fi
# shellcheck disable=SC1090
. "$BOT_ENV"
BOT_PW_FILE="$TEAM_RT/dh-bot.password"
printf '%s' "$DH_BOT_PASSWORD" > "$BOT_PW_FILE"
chmod 600 "$BOT_PW_FILE"
curl -s --cacert "$APPMESH_CA" -X POST -H "Authorization: Bearer $APPMESH_BEARER_TOKEN" -H "Content-Type: application/json" \
	-d '["app-run-task","app-view","app-output-view"]' "${APPMESH_URL}/appmesh/role/digital-human" >/dev/null || true
printf '%s' "$DH_BOT_PASSWORD" | bash "$AUTH_SCRIPT" add-user "$DH_BOT_USER" digital-human >/dev/null 2>&1 || true
# 探测 dh-bot 密码流是否可用（--data-urlencode 防特殊字符）
if curl -s -u 'appmesh-cli:' -X POST "$TOKEN_URL/auth/token" \
	-d 'grant_type=password' --data-urlencode "username=$DH_BOT_USER" \
	--data-urlencode "password=$DH_BOT_PASSWORD" \
	-d 'scope=openid audience:server:client_id:appmesh-api' | grep -q access_token; then
	echo "==> 运行时凭据: 专用最小权限账号 $DH_BOT_USER（角色 digital-human）"
	rm -f "$TEAM_RT/admin.password" # 上次回退遗留，不再需要
else
	rm -f "$BOT_PW_FILE" # 死凭据；路径发现 dh-bot 优先，留着必然认证失败
	# 回退管理员密码文件（DH_ADMIN_PASSWORD 原样写入 600 文件，不进任何脚本正文）
	if [ -n "${DH_ADMIN_PASSWORD:-}" ]; then
		BOT_USER_FOR_HINT="$DH_BOT_USER"
		BOT_PW_FILE="$TEAM_RT/admin.password"
		printf '%s' "$DH_ADMIN_PASSWORD" > "$BOT_PW_FILE"
		chmod 600 "$BOT_PW_FILE"
		DH_BOT_USER="admin@appmesh.local"
		echo "    警告: dh-bot 密码流不可用，回退管理员账号（仅限开发）。启用最小权限账号请 sudo 运行:"
		echo "    printf '%s' '$DH_BOT_PASSWORD' | sudo $AUTH_SCRIPT add-user $BOT_USER_FOR_HINT digital-human"
	else
		BOT_PW_FILE=""
		rm -f "$TEAM_RT/admin.password"
		echo "    警告: dh-bot 密码流不可用且未设置 DH_ADMIN_PASSWORD — 运行时无凭据，"
		echo "    IM 适配器与技能将无法认证（启动即失败）。请 sudo 启用 dh-bot，或 export DH_ADMIN_PASSWORD 后重跑。"
	fi
fi

# ---- venv（claude-agent-sdk 需要 Python >= 3.10）----
VENV="$RUNTIME/venv"
if [ ! -x "$VENV/bin/python" ]; then
	echo "==> 创建 venv (${DH_PYTHON:-python3.14})"
	"${DH_PYTHON:-python3.14}" -m venv "$VENV"
fi
echo "==> 安装依赖（appmesh + claude-agent-sdk）"
"$VENV/bin/pip" install -q --disable-pip-version-check --upgrade pip
"$VENV/bin/pip" install -q --disable-pip-version-check -r "$LLM_DIR/requirements.txt" "appmesh>=3.0.10" # 3.0.10 起提供 PasswordGrantProvider

mkdir -p "$TEAM_RT/workspace" "$TEAM_RT/apps"

render() { # render <模板> <输出>
	sed \
		-e "s|@TEAM@|$TEAM|g" \
		-e "s|@PKG@|$PKG|g" \
		-e "s|@RUNTIME@|$TEAM_RT|g" \
		-e "s|@WORKSPACE@|$TEAM_RT/workspace|g" \
		-e "s|@KB_DIR@|$KB_DIR|g" \
		-e "s|@VENV_PY@|$VENV/bin/python|g" \
		-e "s|@LLM_DIR@|$LLM_DIR|g" \
		-e "s|@TCP_API@|$TCP_API|g" \
	-e "s|@HOME@|$HOME|g" \
	-e "s|@TOKEN_URL@|$TOKEN_URL|g" \
	-e "s|@BOT_USER@|$DH_BOT_USER|g" \
	-e "s|@BOT_PW_FILE@|$BOT_PW_FILE|g" \
		-e "s|@APPMESH_URL@|$APPMESH_URL|g" \
		-e "s|@APPMESH_CA@|$APPMESH_CA|g" \
		-e "s|@IM_PORT@|$IM_PORT|g" \
	-e "s|@IM_BIND@|$IM_BIND|g" \
	-e "s|@IM_TOKEN@|$IM_TOKEN|g" \
		"$1" > "$2"
}

# ---- 技能 App ----
for tpl in kb-search jira-query sys-info oa-approval ops-action; do
	render "$PKG/apps/$tpl.yaml" "$TEAM_RT/apps/$tpl.yaml"
	echo "==> 注册技能 App: $TEAM-$tpl"
	appm -H "$APPMESH_WSS" add -D "$TEAM_RT/apps/$tpl.yaml" -f >/dev/null
done

# ---- IM 适配器 App（P1-1 mock 模式）----
render "$PKG/apps/im-adapter.yaml" "$TEAM_RT/apps/im-adapter.yaml"
echo "==> 注册 IM 适配器: $TEAM-im-adapter (端口 $IM_PORT)"
appm -H "$APPMESH_WSS" add -D "$TEAM_RT/apps/im-adapter.yaml" -f >/dev/null

# ---- 大脑 App（复用 src/apps/llm-agent）----
if [ "$NO_AGENT" -eq 0 ]; then
	# R3: 复用本机 Claude Code 的模型配置（~/.claude/settings.json 的 env 块）；
	# 没有则渲染为空，后续可手工编辑 runtime/<team>/apps/agent.yaml 或用 -z 注入密钥。
	_val() { python3 - "$1" <<'PY'
import json, os, sys
try:
    env = json.load(open(os.path.expanduser("~/.claude/settings.json"))).get("env", {})
except Exception:
    env = {}
print(env.get(sys.argv[1], ""))
PY
	}
	sed \
		-e "s|@ANTHROPIC_BASE_URL@|$(_val ANTHROPIC_BASE_URL)|" \
		-e "s|@ANTHROPIC_HAIKU@|$(_val ANTHROPIC_DEFAULT_HAIKU_MODEL)|" \
		-e "s|@ANTHROPIC_SONNET@|$(_val ANTHROPIC_DEFAULT_SONNET_MODEL)|" \
		-e "s|@ANTHROPIC_OPUS@|$(_val ANTHROPIC_DEFAULT_OPUS_MODEL)|" \
		-e "s|@API_TIMEOUT_MS@|$(_val API_TIMEOUT_MS)|" \
		-e "s|@AUTO_COMPACT_WINDOW@|$(_val CLAUDE_CODE_AUTO_COMPACT_WINDOW)|" \
		"$PKG/apps/agent.yaml" > "$TEAM_RT/apps/agent.yaml.tmpl"
	render "$TEAM_RT/apps/agent.yaml.tmpl" "$TEAM_RT/apps/agent.yaml"
	rm -f "$TEAM_RT/apps/agent.yaml.tmpl"
	AUTH_TOKEN="$(_val ANTHROPIC_AUTH_TOKEN)"
	echo "==> 注册大脑 App: $TEAM-agent"
	if [ -n "$AUTH_TOKEN" ]; then
		appm -H "$APPMESH_WSS" add -D "$TEAM_RT/apps/agent.yaml" -z "ANTHROPIC_AUTH_TOKEN=$AUTH_TOKEN" -f >/dev/null
	else
		echo "    警告: 本机未找到 ANTHROPIC_AUTH_TOKEN（~/.claude/settings.json），大脑未配密钥"
		appm -H "$APPMESH_WSS" add -D "$TEAM_RT/apps/agent.yaml" -f >/dev/null
	fi
	# appm add -D 会把含 secret_env 的完整定义回写到 -D 文件，收紧权限防止本机泄漏
	chmod 600 "$TEAM_RT/apps/agent.yaml" 2>/dev/null || true
fi

# ---- Workflow 示例（复用 Workflow 引擎）----
render "$PKG/workflows/daily-digest.yaml" "$TEAM_RT/apps/daily-digest.yaml"
echo "==> 注册 Workflow: $TEAM-daily-digest"
appm -H "$APPMESH_WSS" workflow add -f "$TEAM_RT/apps/daily-digest.yaml" >/dev/null || \
	echo "    （workflow 注册失败可稍后手动重试，不影响技能与大脑）"

# ---- 技能清单（写进大脑 system prompt 引用的位置）----
cat > "$TEAM_RT/SKILL_CATALOG.md" <<EOF
# $TEAM 数字人技能清单

调用方式: \`bash $PKG/skill <名称> '<JSON>'\`，返回 JSON。

## kb-search — 检索知识库（制度/流程/指南，语义检索）
\`{"query": "报销 流程", "top_k": 3}\`

## jira-query — 查询工单（mock 数据）
\`{"action": "search", "assignee": "zhangsan", "status": "open"}\` 或 \`{"action": "get", "key": "OPS-101"}\`

## sys-info — 查询节点状态
\`{}\`

## oa-approval — 审批登记与确认
创建: \`{"action": "create", "title": "重启订单服务", "requester": "zhangsan", "risk": "high"}\`
确认: \`{"action": "approve", "id": "AP-xxxx", "by": "wangwu"}\`（或 reject）
查询: \`{"action": "status", "id": "AP-xxxx"}\` / 列表: \`{"action": "list", "pending_only": true}\`

## ops-action — 运维操作（高危走审批闸门）
低危直查: \`{"action": "status-check", "service": "nginx"}\`
高危重启: 先 \`{"action": "restart-service", "service": "nginx", "requester": "zhangsan"}\` 会返回 approval_required 和 approval_id；
等 oa-approval approve 之后，携带 approval_id 重试同一请求才会执行。
EOF

echo
echo "部署完成: team=$TEAM"
echo "  冒烟: cd $PKG && $VENV/bin/python chat.py --team $TEAM --skill sys-info '{}'"
[ "$NO_AGENT" -eq 0 ] && echo "  聊天: $VENV/bin/python chat.py --team $TEAM"
echo "  流水线: appm -H $APPMESH_WSS workflow run $TEAM-daily-digest -f"
