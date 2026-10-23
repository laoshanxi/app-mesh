# 数字人集成包（Team Digital Human）

基于 App Mesh 的团队级数字人。数字人回答内部问题，并代替用户执行内部操作。

## 1. 用途

数字人是团队内部的问答与办事入口。成员用一句话提出请求。数字人查询内部系统，给出答案，或代为执行操作。

| 你说 | 数字人做 |
|---|---|
| 「报销时限是多少？」 | 检索团队知识库，引用原文回答 |
| 「zhangsan 有哪些未完成工单？」 | 调用工单技能，返回工单列表 |
| 「帮我重启 order-api」 | 登记审批单；审批人确认后执行重启 |
| 「每天早上汇总知识库更新」 | workflow 定时流水线，产出摘要 |

适用对象：

- **团队成员**：经 IM 或终端提问、办事。每人有独立会话与个人内容空间。
- **team 维护者**：一条命令搭建本 team 的数字人。按第 6 节扩展技能，接入本 team 的系统。
- **平台侧**：App Mesh 提供执行、权限与审批基础设施。本包不修改 daemon。

当前为 Phase 1（开发验证）状态。IM 回复、向量检索、工单数据均为 mock，替换点见 DESIGN.md 第 11 节。

技术要点：大脑复用仓库自带 llm-agent（零改动）；技能是常驻 App（`run_task` JSON 接口）；编排复用 Workflow 引擎；高危操作必须通过审批闸门。设计与需求见 [DESIGN.md](DESIGN.md)。

## 2. 前置条件

1. 目标节点运行 App Mesh daemon（REST 6060 / TCP 6059 / WSS 6058 已开放）。
2. `appm` CLI 可用，并已执行 `appm logon`（全新安装必须先 logon，见 DESIGN.md 第 9 节）。
3. Python ≥ 3.10 可用（默认 `python3.14`，可用 `DH_PYTHON` 覆盖）。claude-agent-sdk 有此硬性要求。
4. 模型凭据可用。默认读取本机 `~/.claude/settings.json` 的 `env` 块。

连接变量示例见 `env.sh`。其他环境按需覆盖同名变量。

## 3. 部署

```bash
cd src/integrations/digital-human
bash setup.sh --team demo                       # 标准部署
bash setup.sh --team sre --kb-dir /data/sre-kb  # 指定团队知识库目录
```

脚本幂等。重复执行安全。执行内容见 DESIGN.md 第 6 节。

IM 适配器默认只监听 `127.0.0.1`。对外暴露时同时设置两项再部署：

```bash
export DH_IM_BIND=0.0.0.0 DH_IM_TOKEN='<随机长串>'
bash setup.sh --team demo
```

设置 `DH_IM_TOKEN` 后，除 `/healthz` 外所有端点要求 `Authorization: Bearer <token>` 或 `X-IM-Token: <token>`。安全边界见 DESIGN.md 第 7 节。

## 4. 部署产物

| App | 作用 |
|---|---|
| `<team>-agent` | 大脑。会话空间 `runtime/<team>/workspace/` |
| `<team>-kb-search` | 知识库检索。TF-IDF mock embedding，可替换为真实向量库 |
| `<team>-jira-query` | 工单查询。mock 数据，可替换为真实 Jira |
| `<team>-sys-info` | 节点状态查询 |
| `<team>-oa-approval` | 审批登记 / 确认 / 查询 |
| `<team>-ops-action` | 运维操作。低危直接执行；高危需审批 |
| `<team>-im-adapter` | IM 适配器。mock 收件箱 + 飞书事件格式 |
| `<team>-daily-digest` | 示例 workflow |

部署同时创建运行时账号（`dh-bot@<team>.local`，角色 `digital-human`，仅三项权限）。root 安装下创建账号需要 sudo。启用命令见 DESIGN.md 第 9 节。账号未启用时，运行时回退管理员 token（仅限开发）。

## 5. 使用

```bash
source env.sh
VENV=runtime/venv/bin/python

# 直接调用技能（不经过模型）
$VENV chat.py --team demo --skill kb-search '{"query": "报销 时限", "top_k": 2}'

# 交互聊天（/skill 直接调技能，/quit 退出）
$VENV chat.py --team demo

# 技能 CLI（大脑会话内同款入口）
bash skill sys-info

# IM 通道（mock 收件箱，默认端口 7070，DH_IM_PORT 可改）
curl -X POST http://127.0.0.1:7070/webhook/mock -d '{"user":"zhangsan","text":"VPN怎么开？"}'
curl http://127.0.0.1:7070/mock/inbox/zhangsan    # 异步取回答

# 示例流水线
appm workflow run demo-daily-digest -f
```

IM 适配器应答模型：webhook 立即返回 202。大脑完成后，答案推入收件箱。模型单轮需要 30 秒至 10 分钟。

飞书回调：`POST /webhook/feishu`。已实现 url_verification 应答、消息事件解析与 event_id 去重。接入真实飞书时，替换 `im/adapter.py` 的 `_reply()` 为飞书回复 API。

## 6. 扩展

### 5.1 新增技能

1. 复制 `skills/sys_info.py`。实现 `handler(dict) -> dict`。
2. 复制 `apps/sys-info.yaml` 模板。修改 `name`、`description`、`metadata.tool`。保留 `@占位符@`。
3. 在 `setup.sh` 的注册列表中加入该技能。
4. 在 `setup.sh` 生成 `SKILL_CATALOG.md` 的段落中加入调用说明。
5. 重跑 `bash setup.sh --team <名>`。

### 5.2 更换知识库

用 `--kb-dir` 指向团队目录（markdown / txt），或直接维护 `data/kb/`。

### 5.3 接入真实系统

参照 `skills/jira_query.py` 的 TODO：替换数据源，保持接口不变。

## 7. 验收清单

Phase 0（2026-10-16）：

- [x] 三个技能 `run_task` 冒烟通过（TCP worker）。
- [x] 大脑真实对话闭环：16 秒/轮，正确调用技能并作答。
- [x] 模型凭据复用本机配置，密钥加密注入。
- [x] workflow 示例跑通（26.8 秒 success）。
- [x] team 参数化部署。

Phase 1（2026-10-16，mock 模式）：

- [x] IM 异步问答：20 秒 / 30 秒两轮实测，答案正确。
- [x] 飞书格式握手与去重。
- [x] kb-search 语义检索排序正确。
- [x] 最小权限账号：run_task 放行，注册 App / 管理 principal 返回 403。
- [x] 审批闸门全流程：申请 → 审批 → 执行 → 状态确认。

系统标准环境与全新安装复验（2026-10-16）：全部项目通过。记录见 DESIGN.md 第 8 节。

## 8. 已知限制

1. IM 回复与审批确认为 mock。真实对接替换点见 DESIGN.md 第 11 节第 1 项。
2. `runtime/<team>/` 下的 agent.yaml 与 dh-bot.env 含密钥（权限 600，不入库）。
3. GLM 网关延迟波动大。IM 已按异步设计。长任务建议使用 workflow。
4. root daemon 下应用以 root 运行。生产环境建议配置 `DefaultExecUser`。

## 9. 文档索引

| 文档 | 内容 |
|---|---|
| [DESIGN.md](DESIGN.md) | 需求跟踪、架构、设计决策、验收记录、已知问题、待办 |
| `env.sh` | 本机连接变量示例 |
| `apps/*.yaml` | App 定义模板（setup.sh 渲染） |
| `workflows/daily-digest.yaml` | workflow 示例模板 |
| `tests/` | 审批闸门与 IM 适配器回归测试。运行：`runtime/venv/bin/python -m pytest tests/` |
