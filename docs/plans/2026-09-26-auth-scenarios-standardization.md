# App Mesh 认证场景规范化计划

日期：2026-09-26
输入：
- CLI 登录认证改进计划（`docs/plans/2026-09-26-cli-login-auth-improvements.md`，**本文取代之**）
- 用户管理 & 体积背景调查（`appmesh-user-mgmt-and-size-notes.md`，代码基准 `6899b611`）

## 背景

两份调查合并后，问题分为三块：

1. **CLI 登录**：默认密码 grant 与 SDK 侧 bearer-only 立场矛盾，且与 OAuth 2.1 移除 ROPC 的方向不符
2. **用户管理**：`dexuser` 管理 UI（127.0.0.1:6064）完全无鉴权；建用户存在"先调用 Engine 冲掉角色绑定"的竞态；Windows 因 memory 存储不支持用户管理
3. **体积/fork 维护**：dex 37 MB（包内单项最大），连接器裁剪未测量、未决策

目标：**以场景为纲规范认证行为**，每个场景有明确、安全、文档化的路径。

## 场景矩阵（目标态）

| 场景 | 目标路径 | 现状差距 |
| --- | --- | --- |
| 桌面交互 CLI | PKCE browser（自动选择） | 默认密码 grant |
| SSH/headless CLI | device flow（自动选择） | 需手动 `--device` |
| 仅内置密码的部署 | 密码 grant（显式 flag，带提示） | 无提示、默认路径 |
| CI/自动化 | `APPMESH_BEARER_TOKEN`（automation-token） | 已规范，需防误用 logon |
| 管理员建/删用户 | add-user → 绑定 → 生效，无竞态 | 竞态已修复（B9） |
| 管理 UI 访问 | loopback 无鉴权，风险接受（已决策） | 风险模型已写入文档（B10） |
| 外部 IdP | PKCE/device，密码 flow 可整体关闭 | password flow 可关（B14） |
| Windows | 文档化限制：不支持动态用户管理，用外部 IdP（已决策）；会话文件 ACL 补齐 | 无用户管理、会话文件无保护 |

## 改动项

### A. CLI 登录规范化（沿用前计划，P0-P2 不变）

1. **默认 flow 自动选择**：无 flag 时按 discovery `flows` + 显示环境检测选 browser/device；仅 password flow 时回退现状并提示。密码登录收为显式 flag
   - `src/cli/src/commands/auth.rs:94-135`、`src/cli/src/app.rs:100-113`
   - flows 不含 password 时由 bail 改为自动尝试 device/browser（`auth.rs:99-101`）
2. **密码 prompt 禁回显**（`src/cli/src/util/password.rs:21-27`）
3. **短名 401 重试仅在 builtin flows 下执行并打印提示**（`auth.rs:118-133`）
4. **Windows 会话文件 ACL 保护**，`ensure_private_file` 不再 no-op（`src/cli/src/util/config.rs:355-356, 195-204`）
5. **discovery 失败降级**：本地 token 未过期则跳过校验直接使用（`src/cli/src/client.rs:72-97`）
6. **`logoff` 撤销失败返回非零**（`auth.rs:207-228`）
7. **`--password-stdin` 恰好一行严格校验**（`password.rs:33-43`，对齐 `appmesh-auth.sh:413-416`）
8. 文档：`docs/source/CLI.md:11-15, 94`、`docs/source/Authentication.md` 按场景矩阵重写登录章节

### B. 用户管理规范化

9. **修复建用户竞态（Part B）**（已完成 2026-09-26，采用首选方案）：provision 前合并磁盘策略（`AuthorizationStore::mergeDiskPolicyLocked`），所有 `saveLocked` 入口先合并再整写，外部绑定不再被冲掉；验收序列已过（含阴性对照）
   - 首选：provision 时**保留已有绑定**（upsert 而非整体重写），从根上消除顺序依赖
   - 次选：add-user 在 Engine 运行时不只打印告警，而是直接调 `POST /appmesh/principal/<id>` 完成绑定（实测 200 可修复）
   - 验收：「建用户 → 用户先调 Engine → 再重启」全序列下角色均生效
10. **管理 UI 风险模型文档化**（已完成 2026-09-26：loopback 无鉴权可接受，不加鉴权层）：`dexuser`（127.0.0.1:6064）维持现状，风险接受依据为"与 gRPC mTLS 暴露模型等同"
    - 将风险模型与 `APPMESH_AUTH_ADMIN_UI=off` 使用指引写入 `docs/source/Security.md` 信任模型章节和 `docs/source/Authentication.md`
    - 明确告诫：不得将 6064 绑定到非 loopback 或挂到反代后面
11. **add-user/delete-user 的传输层回归直连**（已决策 2026-09-26：**不恢复直连 gRPC**，维持 curl → dexuser UI 路线）
    - 评估结论：curl 路径无实际正确性缺陷。UI 是包内版本钉死的组件（dex fork 的 example-app 随包发布），303 `?notice=`/`?error=` 契约逐版本固定；`src/auth/test_admin_ui.sh` 在 CI 每个容器构建中覆盖建用户+登录 200、重复建失败、静态账号守卫、删除+登录 401、删不存在用户失败——假阳性成功会立刻打红 CI
    - "依赖 UI 开启"是刻意语义而非缺陷：`APPMESH_AUTH_ADMIN_UI=off` 是 operator 主动收缩攻击面的开关，用户管理随之不可用与意图一致（B10 已文档化）
    - 恢复直连的成本：重新引入 protowire helper（约 534 行 Go、+5.5 MB，官方 gRPC 客户端曾达 10.7 MB），手工维护对 fork `api.proto` 的 wire 编码，恢复 a501ebc2 删掉的构建/打包路径——而能力零增量（gRPC 与 UI 使用同一 mTLS 材料与 loopback 可达性），且与 6899b611 的包体积收缩方向相反
    - 触发重评的条件：包内出现长期维护的 gRPC 客户端（如 B13 迁移落地），或 dex fork 的 UI 契约发生不兼容变更
12. **Windows 用户管理文档化限制**（已完成 2026-09-26：不补 sqlite，Windows 上动态用户不持久，动态用户管理请用外部 IdP）
    - 文档明确"Windows 仅内置 admin/guest 静态账号是持久的；add-user/delete-user 可用但 memory 存储重启即丢，持久动态用户请用外部 IdP"，写入 `docs/source/Authentication.md`
    - 核对发现 ps1 **实际有** add-user/delete-user 入口（与原假设不符），已按其真实行为（memory 存储、重启即丢、孤儿绑定）撰写文档并补充 Add-User 警告话术，未动功能
13. **admin/guest 静态密码的生命周期**（已决策 2026-09-26：**不迁移**，admin/guest 保持 `staticPasswords`，改密维持"写 hash 文件 + 重启生效"）
    - 评估结论：三条约束都不干净，实施门槛未达到
    - **Windows 无法干净处理**：Dex 在 Windows 用 memory 存储，passwordDB 重启即丢，迁入后 launcher 必须在每次 Dex 启动后经 gRPC 幂等重建 admin/guest——而 gRPC 监听只在 mTLS 材料齐备时才渲染（今天是可选的），迁移会把首次登录的正确性强绑到 gRPC 可用性上，种子写入失败即全新安装整体锁死；staticPasswords 恰好天然扛 memory 存储。仅 Linux/macOS 迁移则要求共用模板按平台条件渲染静态段（新一对标记），正是 dex.yaml 双侧分叉的前科场景
    - **bootstrap 时序需大改**：现为"凭据文件 → 渲染 staticPasswords → dex serve"的静态单序；迁移后为"serve → 等 gRPC 就绪 → 种子写入"的并发时序，sh/ps1 的 `service` 动作都要重排，且首管理员 enrollment 依赖种子落库，失败窗口即锁死
    - **传输层矛盾**：种子写入与即时改密都需要 gRPC 客户端——正是 B11 决定不重新引入的二进制；改走 dexuser UI 则让首次登录依赖 UI 开启，与 `APPMESH_AUTH_ADMIN_UI=off` 语义冲突
    - **收益有限**：初始管理员改密是低频操作，Dex 作为 system App 由 daemon 托管，重启成本低且与运维动作天然对齐
    - 附带语义问题：迁移后 set/rotate 须双写（凭据文件仍是重启恢复与 print-initial-password 的权威源 + gRPC 即时生效），引入新的不一致失败模式
    - 触发重评的条件：包内出现长期维护的 gRPC 客户端（届时 B11 一并重评），或 Dex 上游让 staticPasswords 可经 API 管理
14. **password flow 可关闭**（已完成 2026-09-26）：`OIDC.password_flow` / `APPMESH_AUTH_PASSWORD_FLOW` 控制 flows 是否 advertise `password`（`SecurityOidc.cpp::authConfig`），sh/ps1 渲染 dex.yaml 时按同一配置决定 grantTypes 是否含 `"password"`（双侧同步，模板漂移即失败）

### C. 体积与 fork 维护（本期不做，已决策 2026-09-26）

dex 连接器裁剪测量与 fork 同步策略文档化均移出本期范围。未来若要重启：测量必须用 `go tool nm`/构建差值（不用 `go list -deps`）、同平台对比。

### D. 方法论约束（贯穿所有改动）

- 任何 `dex.yaml` 模板改动必须 sh/ps1 双侧同步（教训 5）
- 体积结论必须同平台对比、用 `go tool nm` 或构建差值验证（教训 1/2/3/4）
- 构建进行中不改仓库（教训 6）

## 测试

- CLI：flow 自动选择矩阵（桌面/SSH × flows 组合）、`--password-stdin` 多行报错、`logoff` 退出码
- 用户管理：建用户四种顺序（9 的验收项，已过）、Windows 文档断言（12，已按 ps1 实际行为撰写）、admin-ui 关闭时 add-user 的行为（已文档化为刻意耦合）
- 回归：现有密码登录、`APPMESH_BEARER_TOKEN`、bootstrap（Linux/macOS/Windows 三平台，防模板回归）

## 兼容性与发布说明

- 破坏性：无参数 `appm logon` 默认行为变化（A1）；B13 已决策不迁移，admin/guest 改密仍需重启（行为不变）
- 不破坏：`--password-stdin`、`APPMESH_BEARER_TOKEN`、服务端 Dex 配置、各 SDK 契约（仍 bearer-only）

## 实施顺序

1. **A1-A3 + B9**（核心行为与竞态修复，安全收益最大）
2. **A4-A7 + B10 + B12 + B14**（细节、文档化决策与配置化）
3. **B11、B13**（用户管理架构调整——评估完成，均决策不实施，仅记录决策）

每步独立可合入；A1 的 password 回退分支保证中间状态兼容。
