# 数字人集成包 — 设计文档

| 项 | 值 |
|---|---|
| 代码位置 | `src/integrations/digital-human/`（不参与 C++ 构建） |
| 基于版本 | app-mesh main（d6a01500 起），系统安装 3.0.1 |
| 文档状态 | 活文档。需求或方案变更时，必须同步更新本文档。 |
| 写作规范 | 遵循 ASD-STE100 简化技术英语原则的中文写法：短句、一句一义、主动语态、术语一致。 |
| 最后更新 | 2026-10-16 |

## 1. 范围

本包实现企业内部数字人。数字人回答企业内部问题，并代替用户执行内部操作。

本包复用 App Mesh 已有能力。本包不修改 daemon 代码。本包包含：

- 技能 connector（可执行的操作）；
- 知识库检索（组织内容）；
- IM 适配器（聊天入口）；
- 审批闸门（高危操作控制）；
- 部署脚本（team 自助搭建）。

本包不含：LLM 服务、向量库服务、真实 IM 平台对接。开发阶段使用 mock 替代（见 R7）。

## 2. 需求跟踪

| # | 需求 | 状态 |
|---|---|---|
| R1 | 基于 App Mesh 实现企业数字人：打通各系统、承载个人/组织内容、提供可执行技能 | 已完成。Phase 0 + Phase 1 验收通过 |
| R2 | 代码放入 app-mesh 仓库 | 已完成。位于 `src/integrations/digital-human/` |
| R3 | 测试阶段复用本机 Claude Code 模型配置 | 已完成。setup.sh 读取 `~/.claude/settings.json`，密钥经 `-z` 加密注入 |
| R4 | 每个 team 自助搭建自己的数字人 | 已完成。`setup.sh --team <名>`，App 名带 team 前缀 |
| R5 | 需求和方案始终保存为 md | 本文档 |
| R6 | 复用现有 llm-agent 与 workflow | 已完成。大脑零改动复用 llm-agent；编排复用 Workflow 引擎 |
| R7 | 开发期间外部依赖可用 mock | 已执行。mock 点见表 3 |

## 3. 架构

```
终端 chat.py / IM / workflow
        │ run_task（JSON 进 / JSON 出）
        ▼
┌────────────────────────────────────────────┐
│ <team>-agent（大脑，复用 src/apps/llm-agent）│
│   │ Bash 调用 skill CLI（daemon RBAC 把关）  │
│   ▼                                        │
│ 技能 App（常驻，fetch_task 循环）：          │
│   <team>-kb-search    知识库检索（TF-IDF）   │
│   <team>-jira-query   工单查询（mock 数据）  │
│   <team>-sys-info     节点状态               │
│   <team>-oa-approval  审批登记               │
│   <team>-ops-action   高危操作（审批闸门）   │
│ <team>-im-adapter     IM webhook（mock 收件箱）│
│ workflow：<team>-daily-digest（示例流水线）  │
└────────────────────────────────────────────┘
```

术语约定：

| 术语 | 含义 |
|---|---|
| 大脑 | `<team>-agent` App。运行 llm-agent，驱动 Claude Agent SDK |
| 技能 | 一个常驻 App。接收 JSON 任务，返回 JSON 结果 |
| 审批闸门 | 高危操作先登记审批。审批通过后才执行 |
| mock | 本地替身实现。替换真实外部系统。接口契约与真实实现一致 |

## 4. 复用清单（R6）

| 复用对象 | 复用方式 |
|---|---|
| llm-agent（`src/apps/llm-agent`） | 大脑。setup.sh 注册 App：`<venv>/bin/python -m llm_agent --server 127.0.0.1:6059`。工作目录指向仓库内 llm-agent 包。不修改其代码 |
| Workflow 引擎 | 多步编排与定时任务。示例：`workflows/daily-digest.yaml` |
| daemon RBAC / OIDC | 认证与授权。技能调用走最小权限账号 dh-bot |
| 事件订阅 / 文件 API | 预留。Phase 2 使用 |

## 5. 设计决策

**D1 技能 = App，接口 = run_task JSON。**
connector 使用 `AppMeshWorkerTCP` 的 fetch/return 循环（`skills/common.py`）。调用方发 JSON，技能返回 JSON。更换实现（如向量库）不改变接口。

**D2 大脑调用技能走 skill CLI。**
交付版 llm-agent 的工具集为 Claude Code 内建工具。大脑通过 Bash 执行 `skill <名称> '<JSON>'`。技能清单写入 `SKILL_CATALOG.md`，并在系统提示词中引用。`LLMAGENT_ALLOWED_TOOLS` 限制为 `Read,Glob,Grep,Bash`。

**D3 模型凭据两阶段。**
开发阶段：setup.sh 读取本机 `~/.claude/settings.json`（GLM 网关），密钥用 `-z` 加密注入。生产阶段：改 App 环境变量（`ANTHROPIC_BASE_URL` 指向企业网关），密钥存 `secret_env`。

**D4 Python 运行环境。**
claude-agent-sdk 要求 Python ≥ 3.10。系统默认 Python 为 3.9。setup.sh 用 `python3.14` 创建 `runtime/venv`。venv 不入库（见 `.gitignore`）。

**D5 高危操作必须审批。**
高危技能第一次调用只登记审批，不执行。审批通过后，调用方携带 `approval_id` 重试。技能校验审批号、风险等级与操作匹配，并防止审批号重用。

## 6. Team 部署模型（R4）

`setup.sh --team <名> [--kb-dir <目录>]` 完成以下动作：

1. 创建 `runtime/venv` 并安装依赖；
2. 渲染 App 定义模板（`@占位符@` 替换为实际路径）；
3. 注册技能 App、IM 适配器、大脑 App、示例 workflow；
4. 创建角色 `digital-human`（仅 `app-run-task` / `app-view` / `app-output-view`）；
5. 创建运行时账号 `dh-bot@<team>.local` 并写入 600 权限密码文件（`runtime/<team>/dh-bot.password`；密码流不可用时改写 `admin.password` 并删除失效的 dh-bot 文件）；
6. 生成 `runtime/<team>/SKILL_CATALOG.md`（技能清单）。

多个 team 部署在同一节点时，依靠 App 名前缀隔离。每个 team 有独立的知识库目录和会话目录。

## 7. 安全模型

| 层 | 措施 |
|---|---|
| 认证 | OIDC bearer（daemon）。管理员用于部署；dh-bot 用于运行时 |
| 授权 | 角色 `digital-human` 仅三项权限。实测：run_task 放行；注册 App 返回 403；管理 principal 返回 403 |
| 密钥 | 模型密钥经 `-z` 加密存储。daemon API 不回显。本机文件（`dh-bot.env`、渲染后的 agent.yaml）权限 600 |
| 高危操作 | 审批闸门（D5）。审批人不得为申请人（`approval.decide` 拒绝自审批）；审批单与操作的绑定 payload 只能由执行方（ops-action）写入，oa-approval 不接受外部 payload；校验与消费由一条条件 UPDATE 原子完成（`approval.consume`），同一审批只执行一次。实测：自审批、伪造 payload、服务不匹配、重复执行均被拒 |
| 审批存储 | `approvals.db`（SQLite）。跨进程（oa-approval 与 ops-action 两个 App）原子性由事务提供：decide/consume 为条件 UPDATE，先到者得；旧 JSON 台账自动一次性迁移（原文件保留 `*.legacy`）；库文件权限 600 |
| IM 入口 | 适配器默认只监听 127.0.0.1（`DH_IM_BIND` 覆盖）。对外暴露必须设置 `DH_IM_TOKEN`：除 `/healthz` 外所有端点要求 `Authorization: Bearer` 或 `X-IM-Token`。请求体上限 1MB（`DH_IM_MAX_BODY`）；Content-Length 非法为负返回 400；非 JSON 对象返回 400；飞书 event_id 去重表有界（`DH_IM_MAX_EVENTS`，默认 1 万）；任务队列有界（`DH_IM_MAX_QUEUE`，默认 200），满时返回 429 |
| 运行时凭据 | SDK `PasswordGrantProvider` + 600 权限密码文件（`dh-bot.password`，回退 `admin.password`）：铸造、过期前刷新、401 后重认证由 SDK 处理；密码文件每次授予时重读，轮换免重启。App 内经 `DH_TOKEN_URL/DH_BOT_USER/DH_BOT_PASSWORD_FILE` 显式注入；chat.py/skill 手工调用按 `runtime/<team>/` 约定路径自动发现。不生成任何铸 token 脚本，密码不进脚本正文 |
| Workflow 注入 | 用户输入注入 JSON 文档必须用 `toJSON()` 表达式（引擎已支持）。示例见 `workflows/daily-digest.yaml`。直接内插会被引号破坏或注入字段 |
| 审计 | 审批记录、执行日志、daemon 日志、会话 transcript |

已知不足：root daemon 下应用进程以 root 运行。缓解：生产环境配置 `DefaultExecUser`。见第 11 节第 9 项。

## 8. 验收记录

### 8.1 Phase 0（2026-10-16，E2E 沙箱）

| 项 | 结果 |
|---|---|
| 三个技能 run_task 冒烟 | 通过 |
| 大脑真实对话 | 通过。16 秒/轮，7 次迭代，13437 tokens，正确调用 kb-search |
| 模型凭据复用本机配置 | 通过 |
| workflow 示例 | 通过。26.8 秒 success |
| team 参数化部署 | 通过 |

### 8.2 Phase 1（2026-10-16，E2E 沙箱，mock 模式）

| 项 | 结果 |
|---|---|
| IM 适配器异步问答 | 通过。两轮实测 20 秒 / 30 秒，答案正确 |
| 飞书格式握手与去重 | 通过 |
| kb-search 向量化（TF-IDF） | 通过。语义近似查询排序正确 |
| 最小权限账号 dh-bot | 通过。权限边界实测（见第 7 节） |
| 审批闸门（大脑驱动全流程） | 通过。申请 → 审批 → 执行 → 状态确认 |

### 8.3 系统标准环境（2026-10-16，/opt/appmesh 3.0.1）

全部项目复验通过：技能冒烟、审批闸门、IM 异步问答（10 秒）、workflow 流水线（21.4 秒）。

### 8.4 全新安装复验（2026-10-16 16:13 重装）

全部项目再次通过：技能冒烟、审批闸门（含伪造审批号拒绝的反向用例）、IM 异步问答（10 秒）、workflow 流水线（24.6 秒）。

### 8.5 对抗审计修复（2026-10-23）

审计发现并全部修复（详见第 7 节安全模型与 `tests/` 回归用例）：

| 攻击面 | 修复前实测 | 修复后实测 |
|---|---|---|
| 审批自审批 | 申请人自批自执，重启执行 | `decide` 拒绝，状态保持 pending |
| 伪造审批 payload | 经 oa-approval 伪造绑定后执行 | oa-approval 不收 payload，consume 校验不匹配 |
| 审批并发写 | 14 次成功创建落盘 11 条 | flock + 独立临时文件，80/80 无丢失 |
| 同一审批并发消费 | check-then-act 竞态 | 锁内原子消费，8 并发仅 1 次成功 |
| IM token 过期 | 401 永久失败（实机 7 天） | 401 重铸重试一次 |
| IM 无鉴权暴露 | 0.0.0.0 任意读写收件箱 | 默认 127.0.0.1；可选 `DH_IM_TOKEN` 鉴权 |
| 恶意请求体 | `Content-Length:-1` 挂线程；非 dict JSON 断连 | 400/413 立即应答 |
| 飞书去重内存 | 无界线性增长（2 万事件 +5.3MB） | 有界淘汰（默认 1 万） |
| workflow JSON 注入 | 一个引号打断 payload | `toJSON()` 表达式（引擎新增） |
| `skill` CA 默认路径 | 指向退役沙箱，调用即 ValueError | 默认 `/opt/appmesh/ssl/ca.pem` |
| `DH_ADMIN_PASSWORD` 特殊字符 | 生成脚本语法错误 | 转义后写入 |

第二轮（同日）补充修复：

| 问题 | 修复前 | 修复后 |
|---|---|---|
| im-adapter 健康检查恒失败 | `>/dev/null` 被 daemon 当字面参数，curl exit 3，`/health` 返回 1 | `-o /dev/null`，live `/health` 返回 0 |
| 401 重试误判 | 答案正文含 "401" 会重发整轮 | 只认错误信封的 message |
| 未读回复堆积 | `_inbox` 无界 | 单户 20 条、全局 1000 条，丢最旧 |
| 令牌比较 | `==` | `hmac.compare_digest` |
| kb-search `top_k` | 非整数抛原始 ValueError；负数切片异常结果 | 友好报错；收敛到 0..50 |
| jira-query 缺字段 | mock 数据缺 assignee/status 整个请求 KeyError | `.get` 容错 |
| sys-info sysconf | 容器中可能抛 OSError | 不可用记 0 |
| chat.py | daemon 错误抛 traceback 中断会话；非对象 payload 直接发出 | 友好报错；提前拦截 |

回归：`tests/` 27 用例通过；workflow 引擎 `go test ./...` 全绿；llm-agent 15 用例通过。

第三轮（2026-10-24，标准化重构，容器复验）：

| 项 | 变更 |
|---|---|
| token 生命周期 | 手搓缓存/401 重试/`DH_TOKEN_CMD` 全部移除，改 SDK `PasswordGrantProvider`（铸造/过期前刷新/401 重认证内建）；token-bot.sh / admin-token.sh 不再生成 |
| 审批台账 | JSON+flock 改 SQLite：事务原子、条件 UPDATE 先到者得、旧 JSON 一次性迁移、0600 |
| setup.sh | 密码文件（600）取代铸 token 脚本；`DH_ADMIN_PASSWORD` 转义块删除；探测用 `--data-urlencode` |
| 兼容 | PyPI 3.0.10 `token_url` 须完整端点，`_token_url()` 归一化兼容 |
| toJSON | 收紧为大小写敏感（对齐 GitHub Actions） |

容器复验（appmesh:latest + 内置 Dex，全新安装）：setup.sh 一次通过且 dh-bot 主路径生效；无静态 token 的 `skill` 调用经 provider 铸 token 成功；自审批/伪造 payload/重复消费全部被拦；`approvals.db`/`ops-exec.log` 0600；适配器 CL:-1 → 400、健康检查 0。`tests/` 23 用例、多进程 90/90、workflow `go test` 全绿。

## 9. 环境记录

| 环境 | 状态 | 说明 |
|---|---|---|
| E2E 沙箱 `/private/tmp/appmesh-e2e` | 已退役 | Phase 0/1 首次验收环境。2026-10-16 停止，端口释放 |
| 系统标准安装 `/opt/appmesh` | 当前环境 | 3.0.1 pkg，root LaunchDaemon。验收见 8.3 / 8.4 |

全新安装注意事项：

1. 先执行 `appm logon` 一次。直接用密码流铸 token 调 API 时，admin principal 无角色（`Permission denied`）。logon 触发角色配置。
2. 重装后删除 `runtime/<team>/dh-bot.env`。旧凭据与新身份库不匹配。重跑 setup.sh 会生成新密码。
3. root daemon 下 Claude CLI 拒绝 `--dangerously-skip-permissions`。已在引擎层修复：`src/apps/llm-agent/llm_agent/claude_sdk.py` 检测 root + `bypassPermissions`，自动设置 `IS_SANDBOX=1`（不覆盖显式设置，输出警告日志）。
4. root 安装下 `print-initial-password` 与 `add-user` 需要 sudo。

dh-bot 账号状态：全新安装后待启用。启用命令（密码见 `runtime/<team>/dh-bot.env`）：

```bash
printf '%s' '<密码>' | sudo /opt/appmesh/script/appmesh-auth.sh add-user dh-bot@demo.local digital-human
```

执行后重跑 `setup.sh --team demo`。运行时凭据自动切换为 dh-bot。当前 dh-bot 密码为开发期占位串。环境升级前必须轮换（delete-user 后用强密码重建）。

## 10. 已知问题与规避

开发过程中确认的问题。新部署遇到相同现象时，按本节处理。

1. **技能 worker 必须走 TCP。** PyPI SDK 的 HTTP worker 被 daemon 以 `managed process proof` 拒绝（403）。`AppMeshWorkerTCP` 原生携带进程证明。`skills/common.py` 已固定 TCP。
2. **客户端 SDK 版本 ≥ 3.0.10。** 旧版对短中文响应按 chardet 猜编码，产生乱码。所有客户端入口统一使用 `runtime/venv` 的 Python。
3. **`appm add -D <file> -z K=V` 会把含密钥的完整定义回写 `<file>`。** setup.sh 对渲染后的 agent.yaml 执行 `chmod 600`。daemon 的 GET API 不回显 secret_env（已验证）。
4. **`appm rm -a <名> --force` 会删除预加载目录中的同名 yaml。** 系统级 App 的 yaml 位于 `<prefix>/apps/`，只在 daemon 启动时加载。修改后需重启 daemon。
5. **bash 默认值陷阱。** `PAYLOAD=${2:-{}}` 在 `$2` 有值时追加字面量 `}`，导致带参调用全部失败。此问题由数字人自身诊断发现。正确写法见 `skill` 脚本。
6. **mock embedding 禁用带符号特征哈希。** 1024 维下哈希碰撞噪声（±0.04）淹没真实信号（≈0.03），且逐进程随机。正确做法：稀疏 TF-IDF 精确向量。
7. **单个 CJK 字符 token 噪声大。** 短文档与查询的余弦相似度失真。向量只使用 CJK bigram 与 ASCII 词。
8. **macOS bash 3.2 的变量名解析。** `$变量` 后紧跟全角字符时，多字节字符并入变量名，触发 unbound variable。正确写法：`${变量}`。
9. **GLM 网关回合延迟波动大（30 秒至 10 分钟）。** 客户端 `run_task` 超时设为 ≥ 300 秒。IM 适配器按异步模式设计（webhook 立即应答，答案推送收件箱）。
10. **automation-token 不适用于数字人运行时。** `appmesh-maintenance` 角色不含 `app-run-task`。因此自建角色 `digital-human`。
11. **`skill` 脚本的 CA 默认路径。** 曾默认指向退役的 E2E 沙箱 `/private/tmp/appmesh-e2e/ssl/ca.pem`，文件不存在导致 SSL 校验抛 `ValueError`。已改为 `/opt/appmesh/ssl/ca.pem`。
12. **`DH_ADMIN_PASSWORD` 含特殊字符曾破坏生成的 admin-token.sh。** `"` 使脚本语法错误，`$` 运行时二次展开。2026-10-24 起不再生成铸 token 脚本：密码原样写入 600 权限的 `admin.password`，由 SDK provider 直接使用，转义问题连根消除。
13. **dh-bot.env 的值必须单引号包裹。** 密码或用户名含特殊字符（如 `<>'`）会破坏 `source` 语法。setup.sh 写入时统一单引号并转义内嵌单引号。
14. **health_check_cmd 不经 shell 执行。** daemon 直接 exec（AppProcess 无 shell），重定向语法（`>/dev/null`）被当作字面参数传给 curl，恒 exit 3，应用被永久判为不健康。静默输出用参数形式（`curl -sf ... -o /dev/null`）。同因，health_check_cmd 不能使用 `&&`、管道、变量展开。
15. **token 重试语义由 SDK provider 负责。** 2026-10-24 起适配器不再手工缓存 token / 匹配 401 文本（答案正文含 "401" 曾误触发重发导致大脑重复处理）。
16. **`PasswordGrantProvider.token_url` 是完整端点语义（PyPI 3.0.10 与仓库 HEAD 一致）。** 传 base URL 会打到 Dex 根路径（404，报 `oauth_request_failed`）。`dh_client._token_url()` 统一补全 `/auth/token`，env 可写 base（与 appmesh-auth.sh 约定一致）或完整端点。
17. **`DH_TOKEN_CMD` 已退役。** 运行时凭据统一走 provider（密码文件）；`skill`/chat.py 凭据二选一：`APPMESH_BEARER_TOKEN`（静态）或 provider 约定路径/env。

## 11. 未完成工作

按优先级排列。当前均为 mock 或未开始。

1. IM 真实对接：`im/adapter.py` 的 `_reply()` 改为飞书回复 API。审批确认从 CLI 改为 IM 回调。增加企微/钉钉格式。
2. 向量库真实化：`KB_EMBEDDING` 接入真实 embedding 与向量库（Qdrant/pgvector）。接口不变。
3. 业务系统真实化：`jira_query.py` 的 `_fetch_issues()` 改为真实 Jira REST。`ops_action.py` 接真实执行通道。
4. 多节点部署：各网段部署节点并配置 forward。connector 就近部署。
5. 定时同步：cron/interval App 与 Workflow 将各系统数据增量同步至知识库。
6. 预算配额：按用户与团队限制 `max_iterations` 与 token 用量。
7. 观测：Prometheus/Grafana 看板（用量、失败率）。
8. 工具面收紧：评估为 llm-agent 增加原生 tools-as-Apps（替代 Bash + skill CLI）。
9. 非特权执行用户：配置 daemon `DefaultExecUser`（`/opt/appmesh/config/config.yaml`，需 sudo 并重启服务）。当前 root daemon 下全部应用以 root 运行。
