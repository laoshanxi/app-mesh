# shellcheck shell=bash
# 本机 App Mesh 系统服务连接（标准安装 /opt/appmesh）— 用法: source 本文件
# 开发期曾用的 E2E 沙箱（/private/tmp/appmesh-e2e）已退役，见 DESIGN.md。
export APPMESH_URL="${APPMESH_URL:-https://127.0.0.1:6060}"
export APPMESH_WSS="${APPMESH_WSS:-wss://127.0.0.1:6058}"
export APPMESH_CA="${APPMESH_CA:-/opt/appmesh/ssl/ca.pem}"
if [ -z "${APPMESH_BEARER_TOKEN:-}" ]; then
	APPMESH_BEARER_TOKEN="$(bash /opt/appmesh/script/appmesh-auth.sh print-initial-password | bash /opt/appmesh/script/appmesh-auth.sh user-token)" || return 1
	export APPMESH_BEARER_TOKEN
fi
