# App Mesh 产品导览

> **一句话介绍**：App Mesh 是一个安全、轻量的守护进程。把它装到你的机器上，机器就变成了一个可托管的算力节点 —— 你可以在这里**承载应用、远程执行、编排流水线、驱动 AI 智能体**。
>
> 一个二进制，覆盖 Linux / macOS / Windows（x86 + ARM）。有 Docker 镜像、deb/rpm 包、Web 控制台、命令行、五语言 SDK 和 MCP 接入。

---

## 它替你解决什么问题

| 你的现状 | 用了 App Mesh 之后 |
|---|---|
| 常驻服务散落在几十台机器，靠 ssh + nohup + 手工重启 | 应用声明一次，崩溃自动拉起、重启后自动恢复、带健康检查 |
| crontab 分散在每台机器，坏了没人知道 | 定时/事件触发集中声明，引擎原生调度，错过不补跑、不重叠 |
| 自动化 = SSH + 胶水脚本，出错靠人肉排查 | 一条命令 / 一次 API 调用把任务发到任意节点，输出实时回流 |
| Jenkins 太重、GitHub Actions 在云端不够用 | GitHub Actions 风格的 YAML 工作流，跑在你自己的机器上 |
| AI 智能体没有安全可控的执行环境 | 内置 LLM 智能体 + 沙箱节点 + RBAC 隔离，密钥加密保管 |
| 团队共用执行平台，权限靠口头约定 | OIDC 单点登录 + 角色权限 + 应用级隔离 + 多租户 |

**类比**：每台机器上的 systemd + 一层 API；或者"跑在你自己机器上的 serverless"。

---

## 六大能力组（按"你想做什么"分组）

### 1️⃣ 应用托管 —— 把进程交给平台

你只需声明"跑什么"，平台负责"一直跑好"：

- 常驻进程 / Docker 应用 / **收编已有进程**，全生命周期远程管理
- 崩溃自动重启（可按退出码区别对待）、守护进程重启后自动恢复
- 健康检查、CPU/内存限额、指定 OS 用户运行、租户隔离
- 保留历史输出，随时回看

```bash
# 注册一个常驻应用（worker）
appm add -a my-worker -c "python3 -u worker.py"
# 看实时输出
appm ls -a my-worker -o -f
```

**典型场景**：数据采集器、模型服务、监控探针 —— 任何"应该一直在跑"的东西。

### 2️⃣ 远程执行与任务调用 —— 把工作发出去

两种姿势，覆盖冷启动和热复用：

- **一次性执行**：命令/脚本发到任意节点，同步等结果或异步流式收输出
- **热任务调用**：向一个**已经跑着**的应用发一条消息、拿回响应 —— 无进程启动开销，天然是轻量 RPC

```bash
# 在 slave1 上执行命令
appm -F appmesh_slave1 exec "df -h"
# 给常驻的 py-task 发一段代码，拿回结果
appm task py-task 'print(sum(range(100)))'    # → 4950
```

**典型场景**：远程巡检、批处理、把重计算丢给特定机器、为常驻服务做轻量 RPC。

### 3️⃣ 调度与自动化 —— 定时和事件驱动

- cron 表达式、固定间隔、起止日期、每日时间窗
- 按退出策略自动化：成功待命 / 失败重启 / 结束自动移除、防 crash 循环限频
- 工作流可被**三种事件**触发：手动、应用事件（某个应用退出/输出时）、**引擎原生 schedule**（cron / `@every`，无需外部 crontab）

```yaml
name: nightly-cleanup
on:
  schedule:
    - cron: "0 2 * * *"        # 引擎原生调度，六段或五段均可，@every 也行
jobs:
  clean:
    steps:
      - name: scrub
        command: "find /data/tmp -mtime +7 -delete"
```

```yaml
on:
  app_event:                   # data-collector 一退出就触发
    app: "data-collector"
    events: [EXIT]
    condition: "exit_code == 0"
```

**典型场景**：夜间清理、定时备份、"进程挂了自动善后"。

### 4️⃣ 工作流编排 —— 把任务串成流水线

GitHub Actions 风格的 YAML，引擎原生执行（不依赖外部调度器）：

- **DAG 依赖**（`needs`）、并行扇出/汇聚、子工作流（可嵌套 4 层）
- 步骤四类：shell 命令、应用执行、**消息（调用常驻应用/LLM）**、子工作流；message 步骤的 `outputs.answer` 只在目标应用按平台信封应答时产生（llm-agent 即是），纯文本应用请引用 `stdout`——引用无答案时引擎明确报错，不把字面量丢给 shell
- 失败处理：`retry`（固定/指数退避）、`continue-on-error`、`finally` 必达清理
- 表达式：`${{ inputs.x }}`、`${{ steps.a.stdout }}`、`${{ jobs.a.steps.b.outputs.answer }}`，`toJSON()` 输出安全 JSON 字面量，条件里可用 `always()/success()/failure()`
- 手动触发可声明**输入参数**（必填/默认值/类型），运行时校验
- 并发组（排队/取消策略）、步骤级超时、运行日志与逐步输出、取消/重跑
- **远程步骤**：按标签或主机把整个 job 指到指定节点
- 严格 schema：写错字段在注册时就报错，不等运行

```yaml
name: release-pipeline
on:
  workflow_dispatch:
    inputs:
      env:      { type: string, default: staging }
jobs:
  build:
    steps:
      - name: compile
        command: "make release"
        retry: { max: 3, backoff: exponential, interval: 2 }
  test:
    needs: [build]
    node_label: { role: test-server }        # 这个 job 在测试机上跑
    steps:
      - name: e2e
        command: "./run-e2e.sh"
      - name: report
        if: "${{ steps.e2e.exit_code != 0 }}"
        command: "echo FAILED | notify-team"
    finally:
      - name: cleanup
        command: "rm -rf ./tmp-artifacts"
```

```bash
appm workflow add -f release-pipeline.yaml
appm workflow run release-pipeline -e env=production -f   # -f 实时跟踪
appm workflow logs -w release-pipeline <run_id>           # 全流程日志
appm workflow detail -w release-pipeline <run_id>         # 每步状态/耗时/退出码
```

**典型场景**：构建-测试-发布、多机巡检流水线、数据管道、任何"有依赖关系的任务图"。

### 5️⃣ AI 智能体 ⭐ —— 把智能接进你的自动化

基于 Claude Agent SDK 构建，是一等公民能力。**三种企业场景：**

#### 场景一：给员工的大模型对话窗口（交互模式）

每个会话一个**专属 worker 应用**，带稳定工作目录和**逐 token 流式输出**——聊天前端订阅一路 STDOUT 事件流，就能多轮对话。跨轮次记忆上下文；会话结束一键关闭，worker 应用和会话数据自动清除。

```python
# 一路订阅，多轮对话，token 实时流出
sub = client.subscribe("llm-agent-sess-S1", ["STDOUT"],
                       callback=lambda e: print(e.data.get("output", ""), end=""))
client.run_task("llm-agent-sess-S1", json.dumps(
    {"action": "session_send", "session_id": "S1",
     "input": "记住数字 7", "stream": True}))
```

实测：「记住数字 7」→「好的，我会记住数字 **7**」→「我让你记的数字是什么？」→「你让我记住的是 **7**。」

已有 AI 客户端？内置 **MCP Server**（OAuth 2.1 保护）让 Claude Code、Codex 或任何 MCP 客户端安全接入并操作平台：31 个工具覆盖应用全生命周期（注册/启停/健康/输出/执行/热任务）、主机资源与指标、配置与日志、标签、主体/角色/权限管理，token 双重校验、全程不碰密码。worker 权限收敛（仅 owner+admin），工具集可收紧（只读、禁 Bash）。

#### 场景二：企业正式的定时 LLM 任务（无人值守运营）

**引擎原生 schedule 触发器** + agent message 步骤：夜间摘要、周期报表、无人巡检。每次运行用独立 `session_id`（如 `${{ workflow.run_id }}`），末尾 `session_close` 自动清理工作区——零残留。

```yaml
name: nightly-digest
on:
  schedule:
    - cron: "0 23 * * *"
jobs:
  digest:
    node_label: { host: "ai-node:6059" }
    steps:
      - name: collect
        command: "journalctl -p err --since today --no-pager | tail -n 50"
      - name: summarize
        message:
          app: llm-agent
          payload: '{"action":"session_send","session_id":"digest-${{ workflow.run_id }}",
                     "input":"审阅今日日志并给出处理建议: ${{ steps.collect.stdout }}"}'
        timeout: 600
      - name: deliver
        command: "echo '${{ steps.summarize.outputs.answer }}' | mail -s '夜间摘要' ops@corp.com"
      - name: cleanup
        message:
          app: llm-agent
          payload: '{"action":"session_close","session_id":"digest-${{ workflow.run_id }}"}'
```

模型回答是一等表达式变量（`outputs.answer`）——可以拿它做条件门禁、发邮件、或链入下一阶段。密钥走 **secured env**（加密保管、任何视图不回显、不落盘）。

#### 场景三：多阶段工作流编排，多模型协作

工作流驱动 agent 完成**共享同一会话的多个阶段**：每一阶段都能看到之前阶段的产出。把不同阶段的 message 步骤指向不同模型的应用，即可多模型协作。

真实运行案例（GLM 网关，总耗时 465 秒）——一个工作流跑完**设计 → 开发 → 测试**全生命周期，全程同一 `session_id`：

| 阶段 | 迭代 | Token | 产出 |
|---|---|---|---|
| 设计 | 2 | 3,320 | 概要：函数签名、规范化规则、边界用例决策表 |
| 开发 | 24 | 19,690 | `palindrome.py`；自行安装 pytest；修掉遇到的 Unicode bug |
| 测试 | 6 | 6,122 | 按概要决策表生成 unittest 套件——**"Ran 5 tests — OK"** |

测试阶段引用了"概要里的决策表"和"之前的编码问题"——同一会话跨阶段携带上下文的实证。在此之上，实测可用：**跨 job 引用回答**、**message→message 链式**（把上一步回答嵌进下一步 prompt）、**DAG 扇出汇聚**（多个 agent 步骤并行，汇聚步合并答案）。

> **运维提示**：手动触发且步骤路由到远程节点时，调用方访问令牌随请求转发（默认 30 分钟有效，引擎不代为刷新）。分钟级长阶段的长流水线，建议运行前重新登录、调大令牌有效期，或改用定时触发（定时运行使用引擎本地能力，不受调用方令牌限制）。

#### 三个场景共同的底座

- **模型自由**：默认 Claude（Anthropic API / Bedrock / Vertex）；经网关可换 **DeepSeek、Qwen、GLM、MiniMax 或任意 OpenAI 兼容模型**——换模型只是换环境变量
- **技能（Skills）**：工作区放一个 `SKILL.md`，所有会话可用
- **成本控制**：`max_iterations` 限制单轮；批量用共享应用，交互用每会话 worker
- **AI 编码沙箱**：官方 agent skill 支持 Claude Code / Codex——本地改代码，远程 Linux 节点构建测试（tar 同步 + SDK 执行）。无需 SSH 密钥、无需 rsync，防火墙后可用
- **参考实现——团队数字人集成包**：`src/integrations/digital-human` 一条命令部署团队数字人（内部知识问答、代办事、高危操作审批闸门），把上面三个场景装进一个开箱即用的包。已实测：知识接地问答、审批登记-执行-防重放全流程

**典型场景**：日志智能分析、AI 值班助手、自动化报告、给全团队一个有 RBAC 治理的共享 AI 执行环境。

### 6️⃣ 集群、文件与平台底座

**集群与多节点**

- 主从架构（compose 一键起全栈），从节点自动同步授权状态
- 任意节点可作入口：`-F` 转发到目标节点执行
- 节点标签（`appm label`）+ 工作流 `node_label`，按能力调度（谁有 GPU 谁跑推理）

**文件分发**

- 上传/下载/删除/覆盖，保留权限属性；跨节点、跨 SDK 一致语义

**事件订阅**

- `START / EXIT / STDOUT / HEALTH / STATUS / REMOVED` 六类事件，TCP/WebSocket 服务端推送，告别轮询

**安全与多租户**

- OIDC/OAuth2 单点登录（内置 Dex，可接企业 IdP）、MFA 与目录策略交给 IdP
- 主体（用户/组/服务账号）+ 角色 + 权限点；应用级读写权限；多租户资源隔离
- TLS 全链路 + 内部 HMAC-PSK；集群授权状态加密复制

**可观测性**

- 内置 Prometheus exporter + Grafana 数据源 + Loki 日志集成
- 主机与应用双维度指标：CPU/内存/启动次数/退出码/健康状态

**接入方式（同一套能力，六种入口）**

| 入口 | 适合谁 |
|---|---|
| `appm` CLI | 运维/开发日常操作，支持命令补全 |
| Web 控制台 | 可视化查看应用/工作流/节点，注册 AI Agent 向导 |
| REST API | 任意语言自研集成 |
| 五语言 SDK（Python / JavaScript / Go / Rust / Java） | 生产级集成，同源测试覆盖 |
| MCP | AI 客户端（Claude / Codex / 自研 Agent） |
| 事件订阅（TCP/WS） | 实时响应型集成 |

---

## 三个端到端业务场景

### 场景 A：夜间多机巡检 + AI 汇总报告

```yaml
name: nightly-inspection
on:
  schedule:
    - cron: "0 23 * * *"
jobs:
  disk:
    node_label: { role: storage }
    steps:
      - name: collect
        command: "df -h /"
  summary:
    needs: [disk]
    node_label: { host: "ai-node:6059" }
    steps:
      - name: ask
        message:
          app: llm-agent
          payload: '{"action":"session_send","session_id":"inspect-${{ workflow.run_id }}",
                     "input":"检查这份磁盘报告，异常则给出处理建议: ${{ jobs.disk.steps.collect.stdout }}"}'
        timeout: 180
      - name: deliver
        command: "echo '${{ jobs.summary.steps.ask.outputs.answer }}' | mail -s '夜间巡检' ops@corp.com"
```

### 场景 B：AI 值班助手（事件驱动）

服务异常退出 → `app_event` 秒级触发工作流 → LLM 读取错误日志给出诊断 → 结论推送到值班群。全程无人在场，密钥不出平台。

### 场景 C：远程构建（跨平台开发）

Mac 上让 Claude Code 写代码，一句"跑下测试" → AI 通过 Remote Sandbox 把代码同步到公司 Linux 测试机 → 远程执行 → 结果流回终端。**本地是 Windows/Mac，构建环境永远干净一致。**

---

## 快速开始（3 分钟）

```bash
# 1. 起一个节点
docker run -d --restart=always --name=appmesh --net=host \
  -v appmesh-work:/opt/appmesh/work laoshanxi/appmesh:latest

# 2. 登录（容器内取初始密码）
docker exec -ti appmesh bash -c \
  '/opt/appmesh/script/appmesh-auth.sh print-initial-password | appm logon -u admin@appmesh.local --password-stdin'

# 3. 跑你的第一个应用
appm add -a hello -c "python3 -u -c 'import time; [print(i) or time.sleep(1) for i in range(10)]'"
appm ls -a hello -o
```

要多节点？`script/docker/docker-compose.yaml` 一条 `docker compose up -d` 拉起 master + 两个从节点 + Web 控制台 + MCP + LLM 节点全栈。

---

## 为什么可以放心用

- **生产级工程质量**：单守护进程、零外部依赖（数据库/消息队列都不需要），有崩溃自愈与资源隔离
- **全链路实测**：五语言 SDK 同一套集成测试矩阵（HTTP/TCP/WSS 三种传输、五百余项断言）、工作流引擎专项（DAG/重试/触发器/远程/并发）、四大参考集成（数字人/MQTT/MCP×2）用户视角端到端、负载下 fd/内存零泄漏验证
- **默认安全**：密钥加密存储不回显、TLS 全链路、最小权限 RBAC、AI 工具集可收敛（去掉 Bash 只留只读）
- **开源**：MIT 协议，文档齐全（[readthedocs](https://app-mesh.readthedocs.io)），镜像在 [Docker Hub](https://hub.docker.com/r/laoshanxi/appmesh)

> 文档基于 App Mesh 3.0.1（2026-11）。所有示例均在六节点 compose 集群上实测通过。
