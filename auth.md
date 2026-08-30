> **状态（2026-08-21）**：Dex-only 认证已实现，实现细节以 [ADR 0009](docs/adr/0009-dex-only-authentication.md) 为准。
> 本文只保留仍然成立的设计原则；早期"随主包分发本地目录服务"的方案已彻底废弃。

# App Mesh Dex 认证设计原则

核心约束：Dex 是唯一认证入口和唯一可信 Token issuer；App Mesh 只做标准 OAuth Resource Server 与自身 AuthZ；所有用户与服务身份都由 Dex 建立。

## 一、架构决策

| 事项 | 决策 |
|---|---|
| 唯一认证入口 | Dex |
| 唯一可信 Token issuer | Dex issuer |
| 内置本地账号 | Dex `enablePasswordDB` + 安装时生成的一个 bootstrap 身份 |
| 外部 Keycloak/Okta/Entra/SAML/LDAP | 全部配置为 Dex Connector（运维自管的 Dex） |
| AppMesh 是否直连其他 IdP | 禁止 |
| AppMesh 是否收集用户密码 | 禁止 |
| AppMesh 是否签发 Access/Refresh Token | 禁止 |
| AppMesh 是否接受旧本地 JWT | 禁止 |
| AppMesh 是否读取 Token 内角色作为权限 | 禁止 |
| AppMesh AuthZ | 本地/集群共享 RBAC，按 `(issuer, subject)` 授权 |
| Web 登录 | Browser Authorization Code + PKCE，直接对接 Dex；Agent 不参与登录 |
| CLI 登录 | System Browser + PKCE；无浏览器时 Device Flow |
| Automation | Dex Client Credentials |
| 集群形态 | 一个集群一个逻辑 Dex，默认单活 |
| 兼容策略 | Major breaking change，不做运行期双认证 |

目标数据流：

```text
内置 bootstrap 用户 ─┐
                     │ Dex password DB (enablePasswordDB)
External IdP ────────┤ OIDC/SAML/LDAP connectors
                     ▼
                    Dex
                     │ OAuth 2 / OIDC
                     ▼
   Web / CLI / SDK / MCP / Agent / Automation
                     │ Bearer Access Token
                     ▼
         AppMesh Resource Server
```

## 二、标准协议基线

所有集成都基于标准发现与标准 flow，不能构造任何 IdP 专用 URL。

| 场景 | 标准 |
|---|---|
| Authorization Server 发现 | OIDC Discovery / RFC 8414 metadata |
| API Bearer Token | RFC 6750 |
| Browser 登录 | Authorization Code + PKCE S256 |
| Native CLI | RFC 8252 loopback redirect + PKCE |
| Headless CLI | RFC 8628 Device Authorization Grant |
| 服务身份 | Client Credentials |
| JWKS | RFC 7517 |
| JWT 验证 | RFC 7519，严格 `iss/aud/exp/nbf/kid/alg` |
| Logout/Revocation | 仅使用 Dex metadata 实际公布的标准 endpoint |
| MCP | OAuth Protected Resource Metadata，Authorization Server 指向 Dex |
| Web Session | Browser-held, memory-only OAuth state；Agent 不持有 OAuth session |

- AppMesh API 只接受 Access Token（靠专用 `aud=appmesh-api` 区分），不接受 ID Token。
- 客户端只知道 Dex issuer，不知道上游 realm、client、JWKS 等信息；Dex 联邦时浏览器由 Dex 重定向到上游 IdP。
- 不支持 password grant；AppMesh 不代理用户名、密码或 TOTP 给 IdP。

## 三、登录与调用流程

- **Web**：public client，直接对 Dex 走 Authorization Code + PKCE（只允许 `S256`），必须校验 `state`/`nonce`/verifier，Access Token 仅存内存、页面状态丢失后重新登录。Agent 只提供静态内容、Dex 反向代理和 Bearer 透传，不是 OAuth client，不持有 client secret，也不生成/交换/刷新/缓存任何 Token；Agent 自身的特权操作必须先取得 Engine 授权决定。
- **CLI**：`appm logon` 起本机 loopback callback + PKCE 打开系统浏览器；`appm logon --device` 走 Device Authorization。无用户名密码登录语义。Token 缓存含 access/refresh/expiry/issuer/client id，文件至少为当前用户独占权限；refresh 直接调用 Dex token endpoint。`appm logoff` 优先调用 Dex 公布的标准 logout/revocation，不支持时本地清理并依赖短 Access Token TTL。
- **SDK**：统一 `TokenProvider` 抽象（static access token / client credentials / refresh token / external callback）。SDK Core 只负责取 Token、设置 Bearer、过期或 401 前请求刷新；不保存密码、不拼接上游 URL、不理解上游 IdP。交互式登录由 CLI/Web 完成。
- **Service account / agent / workflow**：一律 Dex Client Credentials，每个服务独立 client（不共享 admin），凭据只放 secured env 或权限受限的 secret 文件；Token 的 `sub/client_id` 映射为 service principal。用户触发的工作流可在内存中传递用户 Token，但长时间、定时或恢复运行必须使用显式声明的 service principal，不持久化用户 refresh token。
- **MCP**：只发布 Protected Resource Metadata（Authorization Server 指向 Dex）并原样转发 bearer；不自建 OAuth server、登录页、authorization code 或密码代理。

内部 `APP_MESH_PROCESS_KEY`（HMAC）只作为本机进程通道的完整性证明：不映射成 principal、不授予权限、不能绕过 Dex Token、不被外部 HTTP/WSS API 接受。

## 四、服务端认证域模型

原 `Security` facade 同时承担密码验证、用户、角色、MFA、Token 与授权，必须拆分为下列部件。

**Principal**，唯一身份键是 `(issuer, subject)`：

```text
Principal
  principal_id       内部稳定 ID
  kind               user | service | system
  issuer / subject   Dex issuer 与 sub
  display_name/email 非权限字段
  connector_id       审计/展示
  status             active | disabled | tombstoned
```

禁止用 username、email、preferred_username、group、上游 user id、LDAP uid 作为授权键或 App owner——这些字段可变。

**OidcTokenVerifier**：唯一 Dex issuer + Discovery + JWKS 缓存；严格校验 `iss` 完全匹配、`aud` 含 `appmesh-api`、`exp`/`nbf`/可选 `iat` 偏移、`kid`、非对称算法 allowlist；display claims 只用于展示与审计。未知 `kid` 触发一次受限刷新并有 negative cache 防打爆 Discovery/JWKS。Dex 不可达时已缓存 JWKS 继续验证现有 Token，其余返回 503，绝不回退本地 JWT。

**AuthorizationStore**：只做 AuthZ——principal 查询/provision/disable、role 查询、`requirePermission(principal, permission, resource)`、role binding 管理。不再包含 password hash、TOTP secret、token epoch、JWT signing key、上游 admin API、refresh token，也不把 IdP group 当权限。单机可用本地文件，集群沿用既有一致性存储（Consul watch 只作为 AuthZ 数据同步手段，不是认证后端）。

**内置账号**：Dex `enablePasswordDB` + 安装时生成的唯一 bootstrap 身份，凭据轮换与 Dex 配置渲染由 `src/auth/appmesh-auth.sh` 完成。完整用户生命周期（建号、改密、MFA、目录组）属于外部身份部署，不是 Engine 职责；不提供与 Dex 并行的 TOTP 通道。

**SecretProtector**：`Resource Owner != Encryption Key != OS Execution User`。节点/集群级 master key（不入代码、不入普通 YAML）+ envelope encryption 保护 secured env 与 connector secret；App owner 不再负责加解密，用户密码变化不影响应用 secret；App 可迁移时相关节点需受控的集群级解密能力；审计谁读写 secret，但绝不记录 secret 值。

## 五、请求管线与错误语义

```text
Bearer 提取 → OidcTokenVerifier.verify → Principal 解析 → requirePermission → resource owner/tenant 检查 → Handler
```

Token 中的 groups/roles 只能作为展示信息、首次 provision 的可选输入或显式配置的 group-to-role 映射输入，不等同 AppMesh permission。

| 场景 | 返回 |
|---|---|
| 无 Bearer Token | 401 + `WWW-Authenticate: Bearer` |
| Token 无效/过期/issuer 错误 | 401 `invalid_token` |
| Token 有效但无权限 | 403 |
| Dex/JWKS 尚未 ready 且无法验证 | 503 |
| Principal disabled | 403 |
| 未知 Principal 且禁止自动 provision | 403 |

权限不足不要返回 400。

已移出 AppMesh 的 endpoint：`/appmesh/login`、`/appmesh/token/renew`、`/appmesh/self/logoff` 的本地 blacklist 语义、`/appmesh/totp/*`、password change、本地 refresh token/JWT minting、任意上游 token proxy。保留 `GET /appmesh/auth/config`（免认证，只返回 issuer、public client id、audience、scopes、支持的 flow，不含 connector secret）、`GET /appmesh/user/self`（本地 Principal 与 RBAC，不代理 Dex `/userinfo`）、`/healthz`、`/readyz` 与 principal/role binding 管理 API；不提供自制 introspection endpoint。

WSS 握手与文件传输使用同一个 Dex Access Token 并执行正常 RBAC；不再签发 `appmesh-file-service` 本地 JWT，也不允许客户端指定特殊 privileged audience。跨节点转发携带原始 Bearer，由目标节点重新验证并检查资源权限。一次性 operation handle 只绑定 `principal_id + operation + path + expiry`，是内部授权 capability 而非身份 Token。

## 六、App owner、OS 用户与 RBAC 数据模型

`User` 不再同时表示登录用户、App owner、OS exec user 与 secret 加密 owner：

```text
Application
  owner_principal_id   OIDC Principal ID
  run_as_policy        独立的 OS execution policy
  owner_permission
  secret_envelope_id   独立 secret key/material
```

- system app 使用内部 system principal；外部用户名不直接映射 OS 用户，上游 group 不直接映射 OS group。
- 删除用户不自动删除其 App：owner 进入 tombstone 由管理员转移，审计保留原 owner principal。

```text
principals (id, kind, issuer, subject, status, display_name, email, connector_id)
roles (id, name)
permissions (key)
role_permissions (role_id, permission)
principal_role_bindings (principal_id, role_id, tenant_id nullable, resource_scope nullable)
applications (owner_principal_id)
service_accounts (principal_id, dex_client_id)
```

## 七、Dex 打包与启动

安装与供应链细节见 ADR 0009 与 [Install](docs/source/Install.md)：Dex 以与 cfssl 同级的方式（`go install`/GOBIN）安装、版本与各平台 SHA256 固定、禁止运行时下载 latest；唯一的认证 System App 是 `script/apps/auth-dex.yaml`，凭据生成、配置渲染（mode-0600 runtime 文件）与密码轮换由 `src/auth/appmesh-auth.sh` 幂等完成。

System App 保护：普通 REST API 不能删除或修改其 command/listener/working dir，不允许远程 disable Dex 把整个集群锁死；升级或停用必须进入本地 maintenance mode；owner 是内部 system principal；崩溃自动 restart。

启动依赖基于 readiness（health probe 首次成功）而非 PID 顺序或目录遍历顺序：

```text
auth-owner: 基础配置/日志/process manager → AuthorizationStore + system principal + SecretProtector
            → 加载 System Apps → 启动 Dex 并等 discovery+JWKS → 预热 verifier → 启动 Agent listener 与普通 Apps
follower:   AuthZ Store + System Apps（不启动本地 Dex）→ 解析稳定 issuer 取 Discovery/JWKS → 对外 ready
```

故障语义：Dex 未 ready 时受保护 API 返回 503，不回退本地账号；Dex 崩溃后自动 restart，已缓存 JWKS 下未过期 Token 仍可用但新登录/refresh 需等恢复；正常关闭先停止接受新登录再停 Dex。

## 八、首管理员 enrollment 与身份绑定

无默认硬编码账号：安装时生成随机 bootstrap 身份 → 首个管理员通过 Dex 完成标准登录 → 一次性 `/appmesh/auth/enroll-first-admin` 把该 `(issuer, sub)` 绑定为第一个 admin principal → 标记 bootstrap 完成并关闭该 endpoint。集群 bootstrap 只能在 auth owner 本地完成，不存在"第一个互联网请求自动成为 admin"。

不要假设 Dex subject 等于登录名。首次登录策略：普通用户可 auto-provision 为 `active + no role` 或最小 `viewer`，admin 永远不能由 email/group 自动获得；connector id 改名可能改变 subject，必须视为身份迁移；不允许按相同 email 自动合并不同 connector 用户，account linking 需管理员显式批准。

## 九、外部 IdP 接入

AppMesh 配置里只有 `issuer = Dex` 与 `audience = appmesh-api`；Keycloak、Okta、Entra、客户 SAML/LDAP 全部只存在于 Dex connector 配置：

```text
AppMesh client ──(only knows Dex)──▶ Dex ──┬── customer-keycloak
                                           ├── customer-saml
                                           ├── customer-oidc
                                           └── customer-ldap
```

`DexConfigManager` 负责：connector schema 校验、connector ID 唯一且创建后不可随意修改、secret 使用引用、原子写入 runtime config、启动前 dry validation、controlled restart 并等待 readiness、失败回滚上一版本、审计变更、不把 connector secret 返回给调用者。集群中只有 auth owner 能修改 Dex config，follower 携带原始 principal 上下文路由过去。

## 十、集群设计

- **单 issuer**：一个集群只能有一个逻辑 issuer（如 `https://auth.<cluster-domain>/dex`），URL 必须稳定、不随 leader hostname 变化。所有节点信任同一 issuer、同一 audience、共享 role binding，不信任节点自己的本地 Dex。
- **Agent 统一入口**：`/dex/*` → active Dex（standalone 指本机 Dex App，follower 指当前 auth owner），`/appmesh/*` → local daemon，`/auth/*` → 本地 callback。Agent 只反向代理、不重写 issuer；必须保留原始 Host/Forwarded headers、TLS 外部 URL 与正确 callback URL，并隔离 API 与 Dex 路由。
- **Auth owner 选择**：首版推荐显式配置固定 `cluster.auth_owner`（简单、无 split-brain、易 air-gap，代价是人工 failover）。可选基于 Consul session/lease 选主，但 lease 只决定谁能启动服务，不解决数据复制：失去 lease 立即停止对外服务，follower 不得用过期数据自动接管。
- **单活硬约束**：没有共享事务数据库或可靠复制存储时，禁止两个实例同时写同一 Dex 数据库、SQLite over NFS 做 active-active、多个独立 SQLite 共用一个 issuer、无 fencing 自动启动第二个 auth owner。只能承诺 `single active + backup + manual/cold failover`；`zero external service + SQLite-only + automatic failover + RPO 0` 无法同时满足，不应通过脚本假装 HA。
- **备份与 failover**：一致性备份 bundle 覆盖 Dex storage、connector config、signing/storage state、principal 与 RBAC binding、encrypted secret metadata、version manifest。切换流程：确认旧 owner 已停止或 fencing → 在 standby 恢复备份并校验版本/schema → 启动 Dex 验证 issuer/JWKS/登录及旧 Token 行为 → 更新 lease/服务发现让 Agent 路由切换 → 恢复管理面并写 failover audit。自动故障转移要等到引入共享 PostgreSQL 或可靠复制存储之后。
- **集群 AuthZ**：同步的数据结构只有 principals、roles、permissions、role bindings、status、application ownership（不含密码、MFA、JWT signing 数据）。每个节点本地执行 `verify Dex token → lookup shared role binding → authorize locally`，不逐请求远程调用 auth owner。

## 十一、配置模型

实际配置见 `src/daemon/security/oidc.yaml`、`authorization.yaml`、`auth-stack.yaml`。AppMesh 侧只存 Dex 公共信任信息：issuer、audiences、discovery/JWKS 策略、principal provisioning 模式、`groups_are_permissions: false`、cluster auth owner。

禁止出现：上游 realm/admin endpoint、上游 JWKS/userinfo endpoint、上游 client role、用户密码、LDAP bind password 明文、Dex client secret 明文。

daemon 访问公共 issuer 存在 hairpin 问题时，可显式配置内部 discovery/JWKS 地址，但 Token `iss` 仍必须验证公共 issuer，且内部地址必须是同一个 Dex——不允许因此信任第二个 issuer。

## 十二、迁移原则

不做运行期双信任（旧 AppMesh JWT + 上游 JWT + Dex JWT）：双信任扩大攻击面且让 owner/role 迁移不可验证。采用离线 major upgrade，不提供自动 fallback。

- 迁移前导出旧 users、roles/permissions、App owners、exec user override、secured env、workflow owners、上游 role mapping；Token blacklist 不迁移。
- 旧本地用户映射到 Dex 内置身份，只有 hash 明确兼容才迁移，否则强制 reset；不迁移 AppMesh TOTP。
- 外部 Keycloak 改配成 Dex OIDC Connector，用户重新登录获得新 subject，旧 client role 转成本地 role binding；不按 email 自动合并，需管理员确认新旧对应关系。
- 旧 username owner 映射到 principal id，未完成映射的 App 进入 `owner_unresolved`（管理员重新归属）；system app 改用 system principal；exec user 单独迁移。
- secured env 顺序必须是「读旧 owner encryption material → 解密 → 用 SecretProtector 重新加密 → 验证 → 才删除旧认证数据」，不能先删旧密码数据。
- 切换：停写 → 完成 AuthZ/owner/secret 迁移 → 启动 Dex 并验证 discovery/JWKS → 切 issuer → 启动 Agent gateway → 旧 Token 全部失效、用户重新登录 → 恢复流量。

## 十三、验证要点与关键风险

验证需覆盖：各标准 flow（PKCE、loopback、device、client credentials、refresh rotation、logout/revocation feature detection、discovery、JWKS rotation）；安全负例（错 issuer、错 audience、ID Token 冒充 Access Token、`alg=none`、算法混淆、伪造/未知 `kid`、过期与未来 `nbf`、token role 权限注入、group/email/connector 变化、disabled principal、CSRF/state/nonce/PKCE replay）；Token 与凭据不落日志、bootstrap 凭据与 Dex runtime 配置为 mode-0600；集群下 follower 验证、Dex 重启、lease 丢失、网络分区、fencing、备份恢复、failover 后旧 Token 行为、无共享存储时拒绝自动双活；迁移用例（local/外部用户、unresolved owner、secured env 重新加密、workflow owner、旧 Token 拒绝、回滚快照）。

关键风险：Device Flow 与 Client Credentials 必须在最终锁定的 Dex 版本上实测，不能只看 feature list；集群没有稳定 DNS/VIP/代理 URL 就做不了标准 OIDC；SQLite 默认只能单活，不承诺 RPO 0；密码 hash 不兼容只能 reset，不能明文搬运；必须先完成 SecretProtector 才能删除旧 User credential model；不允许按 email 自动 linking，避免不同 connector 账号接管旧资源；AppMesh/SDK 不直接访问上游 IdP，但浏览器执行上游 OIDC/SAML 登录时仍会访问上游域名。
