# karing-tui-v2 MVP 实施计划（先完成可用闭环）

> 文档状态：**实施蓝图已编制；功能及验收尚未宣称完成**  
> 制定日期：2026-11-07  
> 工作基线：`feat/m0-m1-foundation` @ `c202531bc0d735f242fd32dc0d74de28fa054164`  
> 上位规范：[完整项目计划](plan.md) `docs/plan.md` · [功能与协议兼容矩阵](compatibility.md) · [仓库 README](../README.md)  
> 适用对象：首个面向真实 Linux 用户、可独立完成核心代理流程的 **MVP Preview/Beta**；**不是**完整 Karing 兼容版或正式稳定版。

## 0. 文档定位和裁决规则

### 0.1 为什么单独规划 MVP

截至此基线，Daemon、SQLite 代际/应用日志、已固定 Core、Rule/Direct/Selected 三入口、五层分流 IR、部分协议编译及 Bubble Tea TUI 已有代码和自动化集成证据，但还无法让普通用户仅通过受支持的 TUI/CLI 稳定完成 **订阅导入 → 节点成为可应用声明 → CN 分流/DNS → 显式应用 → 真实代理流量 → 关闭/重启 → 备份恢复**。现有 `docs/plan.md` 无单独的 MVP 定义，`M5` 的大量局部加固不等于这些端到端路径已完成。

本计划定义一个可以**判定通过或失败**的首个可用版本。所有通过项必须有执行记录和可追溯提交；“代码存在”“编译通过”“模型能生成 JSON”“Go race 通过”**不能**单独视为用户功能已交付。

### 0.2 优先级和不退化约束

本文件是 `docs/plan.md` 的**交付切片**，不改写其 P0/P1、R01–R12、T01–T26、M0–M6 和正式版完成定义。冲突时，采用更保守的安全、数据完整性与兼容性门槛。

- **运行范围**：Linux amd64/arm64、普通 UID、无需 root 或网络管理 capability；Daemon 与 TUI 分离；固定且可复现的 KaringX/sing-box Core。不实现 TUN、TPROXY、redirect、系统路由/防火墙接管、默认系统代理修改。
- **分流不可简化**：Custom → GeoSite → GeoIP → ACL → FINAL，保留来源开关、顺序、组目标、DNS 绑定、地区追加、显式阻断、来源解释；**订阅/ISP 不属于分流层**，订阅携带的 route/rules/MATCH/FINAL/rule-provider/ISP 规则必须剥离并报告。
- **CN 不可偷换**：固定来源的 28 个预设组、6 组默认开启、原顺序、默认目标与独立地区追加必须保留；不能用“国内直连/国外代理”两条规则声称支持 Karing CN。
- **失败关闭**：丢失解析器、节点、授权规则资源、Core 能力、配置或应用确认时，不得静默转 DIRECT；配置应用为显式事务，不自动无限重试，不覆盖唯一有效代际。
- **许可与隐私**：凭据不得进入命令行参数、日志、诊断或 PR 证据；不能分发来源/许可未核实的 CN 资源。离线启动必须使用已验签、经来源许可审计的完整本地资源闭包。
- **恢复权限**：既有 inert restore 的 `RestoreReady=false` / `RestoreSupported=false` **不得仅因 MVP 目标而改成 true**；没有完成真正的恢复安全验收，就不能宣称支持恢复或发布可交付 MVP。

### 0.3 两个不同发布结论

| 级别 | 可做什么 | 不允许的宣称 |
| --- | --- | --- |
| 内部技术预览 / Pre-MVP | 受控本机或临时 VM，合成声明、局部导入、只读恢复预检；可带明确缺口 | 不能称为可交付 MVP，也不能暗示 CN/真实恢复可用 |
| **MVP Preview/Beta（本计划完成定义）** | 新用户无需手改运行 JSON，可完成本文件 `2–`7` 的真实端到端流程，关键数据安全与离线要求已验证 | 不得称“全面兼容 Karing”“长期稳定正式版” |
| 正式稳定兼容版 | 按 `docs/plan.md` M5 / T01–T26 全部适用门槛、7 天与 30 天长稳、P0 完整兼容、许可证与发行条件通过 | 本计划不缩减该标准 |

任何关键安全、恢复、CN 许可或规则语义门槛未过时，只可保留内部技术预览标签，不能发布 MVP Beta。

## 1. 当前基线和主要缺口

以下是 2026-11-07 的**文档/代码状态快照**，不是新的验收判定；具体实现以合入时提交与回归结果为准。

| 领域 | 已有基础 | 达到 MVP 前仍需补齐 |
| --- | --- | --- |
| 服务与 Core | Daemon/API、SQLite 代际 journal、有限重启监督、真实受控 Core、三个 loopback Mixed 入口 | 两架构普通用户安装、真实用户路径的持续运行与故障回退 |
| 分流与 DNS | 五层 IR、类型化目标、组 DNS 编译与多项受控真实 DNS/流量实验 | **CN 28 组从快照到可执行 IR 的完整转换**；真实 CN 五层冲突、DNS 路径和地区追加联合验收 |
| CN 资源 | 28 组/6 默认开启源快照，规则引用来源盘点 | 当前 `cn_preset_snapshot=true`、`cn_preset=false`；完整离线闭包、`geoip:bing` 缺口与再分发许可尚阻断 |
| 订阅/节点 | sing-box 基础导入、Shadowsocks URI 子集、快照/CAS/节点覆盖、部分协议编译 | Clash/V2Ray 常用来源、TUI 安全导入入口、**快照 → 用户确认声明 → Core 受控应用**闭环 |
| TUI | Dashboard、Profiles/Nodes、CurrentSelected、部分 Routing 启停/目标/DNS 暂存、只读 DNS/连接与确认应用 | 新用户初始化、来源导入/更新、CN 规则操作、错误诊断与恢复的最小完整流程 |
| 备份与恢复 | 一致性快照/加密归档/恢复候选及大量**内部只读**防护 | 实际受控备份与可信恢复、恢复前验证与回退；Issue [#59](https://github.com/bbbstyyy/karing-tui-v2/issues/59) `create_scope` 偶发拒绝根因未确认 |
| 验收/发行 | Go CI、4 个 race 分片、Managed Core、双架构 Core Provenance 和短周期禁网合成流量 | 全流程实测、MVP 72h 验证、两架构完整离线安装包及许可/来源清单 |

依赖中的未集成工作：[#100](https://github.com/bbbstyyy/karing-tui-v2/pull/100)（ADR 0220）与 [#101](https://github.com/bbbstyyy/karing-tui-v2/pull/101)（ADR 0221）于本计划制定时仍是 Draft/堆叠 PR；其 CI 通过不代表已进入开发基线。按原完整 CI 门槛独立完成集成，不让其长期阻塞下述无关的 MVP 纵向切片。

## 2. 首个 MVP 的用户任务与功能边界

### 2.1 必须完整通过的用户故事

一个此前没有项目数据库的 Linux 普通用户，可以：

1. **安装和启动**：在 amd64/arm64 无 root 环境安装带来源清单的程序/Core/CN 资源；用文档化的 user systemd 或前台 Daemon 启动。退出 TUI/SSH 会话不影响已托管进程（lingering 条件需明确）。
2. **导入来源**：在 TUI 或受保护 CLI 中新增订阅/导入本地文件；显示格式、支持节点数、拒绝原因及被有意忽略的订阅分流，不回显 token、节点口令或原始恶意字段。
3. **确认节点进入运行声明**：展示快照变更（新增、移除、保留和受影响绑定），经 CAS/预览/人工确认才生成**可应用的声明**；不能停留在仅可预览的快照或要求手工编辑 Core JSON。
4. **启用 CN 分流与 DNS**：可从 28 个预设组选择、编辑必要的启停/目标/组 DNS、独立设置地区追加；真实 Core 中五层先后顺序与 DNS 出站正确。缺失授权资源时失败并说明，而非替换成两条简化规则。
5. **显式应用并代理**：检查编译摘要与旧/新代际，人工确认后 Core Check → 激活 → 健康验证 → 持久提交；Rule/Direct/Selected 三入口能通过真实 SOCKS5/HTTP 流量说明差异，用户可更改 CurrentSelected。
6. **故障与日常维护**：可查看运行状态、节点/订阅最近成功时间、错误原因、分流模拟/实测归属及 DNS 绑定；坏订阅、超时、被拒节点、错误规则和 Core 崩溃不破坏最后有效状态。
7. **重启及恢复**：重启 Daemon/主机后能使用原配置离线运行；能创建可验证的一致性备份，并在严格校验、隔离及人工确认下**真正恢复到已知有效状态**，失败不覆盖现有运行代际。

任何故事仅能通过手工构造内部测试对象完成时，标记“内部夹具通过”，不能计为用户故事完成。

### 2.2 MVP 要支持的最小但真实的协议/订阅面

- **入口**：真实 SOCKS5 和 HTTP CONNECT，包含 IP/域名；UDP 仅在相应组合有 Core 行为证据时显示为受支持，未验证组合必须明确拒绝。
- **节点子集**：优先完成已实现基础域模型的 Shadowsocks、VLESS、Trojan；HTTP/SOCKS、VMess 基础子集保持既有回归。至少对 Shadowsocks + VLESS + Trojan 的**受支持字段组合**建立从订阅到真实 Core 的全链路夹具，包含明确的 TLS/认证失败情况。
- **来源格式**：MVP 必须有本地 sing-box JSON 以及至少一个广泛使用的订阅格式（优先 Clash/YAML，外加 V2Ray/Base64 URI 常用子集作为后续并行任务）。该最小兼容面要在 `docs/compatibility.md` 逐字段声明；未支持协议/transport/TLS 属性必须整项拒绝或标记不可应用，不得静默丢字段。
- **手动刷新先于自动调度**：MVP 必须能安全手动刷新并保留上次成功快照。自动定时更新、广谱测速、全部来源提供商特性与高级协议覆盖保留在完整 P0 计划中，可在 MVP 后扩展；不能误导成已实现。
- **界面**：MVP TUI 只需覆盖上述关键工作流，不必具备所有高级设置/历史统计页面；需要显式显示“未应用”“模拟/未知”“旧代际”“恢复需人工处理”等状态。

### 2.3 暂不纳入 MVP 的扩展项

Karing 备份迁移、WebDAV/LAN 同步、二维码工作流、WARP、前置代理链、完整高级 TLS/Reality/uTLS/Mux、Hysteria2/TUIC 全面兼容、所有动态 regex 自动组选项、自动规则更新、30 天长期稳定**发行认证**等可继续按完整路线图推进。**延期不允许静默接受未支持的输入**，且不得改变用户明确要求保留的五层分流、CN 规则或无 TUN 约束。

## 3. 交付主线和实施顺序

每一个工作包必须独立可测试、可回滚；下方“待实现”是任务，不暗示当前已经完成。不按日历估算完成时间，按出口门槛推进。

| 阶段 | 优先级 | 必须实现的工作 | 出口证据 / 依赖 |
| --- | --- | --- | --- |
| **MVP-0：冻结可用基线** | P0 | 对齐开发分支、消化 #100/#101 的完整 CI 与依赖；锁定 Core/工具链；建立从空状态到 Core 流量的统一集成夹具 | 两架构无特权真实 Core 可以运行；失败场景保留 LKG；不阻塞其它独立任务 |
| **MVP-1：订阅到生效声明** | **最高** | 完成来源导入、快照对账、参数不丢失、节点/覆盖绑定、用户确认的 snapshot→declaration CAS、显式 apply/readback；接入至少一个普通用户可操作来源格式 | 一份真实可读订阅经 CLI/TUI 进入可应用声明，再到 Core 三入口；订阅规则不注入；失效更新保持现有代际 |
| **MVP-2：完整 CN 分流可执行化** | **最高** | 28 组原条件到带来源证据的布尔 IR；地区追加独立开关；授权/完整的规则集离线闭包；用户覆盖迁移和冲突行为 | 28 组/6 默认、五层命中、FIRST/FINAL/阻断/组 DNS 的**真实流量**证据；两架构禁网启动 |
| **MVP-3：最小 TUI 闭环** | P0 | 初始化、来源/节点选择与刷新、CN 组必要编辑、DNS 绑定、预览/应用、状态/诊断；所有写操作需确认与 CAS | 新用户在 TUI/安全 CLI 完成 `2.1` 前六项，不手改运行 JSON；断线/窄屏/中文/恶意终端输入通过 |
| **MVP-4：备份与真实恢复** | P0 安全门槛 | 完成真实备份导出、独立恢复预检、明确目标代际、受控恢复及失败回滚；复现并根治 #59；恢复实验覆盖中断/不确定状态 | T15/T23 对实际启用的恢复路径有故障注入和重启后的 DB/journal/Core/资源一致性证明；不允许仅将原禁用标志改为 true |
| **MVP-5：交付验证与候选包** | P0 | 两架构无特权冷安装、可审计 CN 规则许可/离线完整性、无下载源启动、72h 连续真实流量与故障混合验证、操作手册/已知限制 | `5` 全部门槛通过，证据与固定提交绑定；可标记 MVP Preview/Beta，但不标记正式稳定版 |

**并行规则**：MVP-1 和 CN 资源**来源/许可证核查**立即并行开展；MVP-2 的规则语义与 DNS 真实流量验证可并行；MVP-3 依赖前两阶段受保护 API 可用；MVP-4 的实验设计与 #59 根因定位应并行但真实恢复授权必须晚于相应验收；MVP-5 只能在所有关键门槛关闭后宣布完成。

### MVP-1 具体拆分（推荐最先编码）

1. **MVP-1A**：以现有 Profile Source/Snapshot、stable NodeID、Overlay、`profiles preview` 为基础，补齐严格的“提议 → 审查差异 → 显式提交声明” API/CLI/TUI，不自动应用到当前 Core。
2. **MVP-1B**：在编译器预检/实际 Core Check 后调用既有有界 ApplyCoordinator，绑定 `declaration revision / config generation / selected revision / Core SHA`；应用回执必须由读取实际已应用代际核对。
3. **MVP-1C**：构造本地订阅 HTTP 服务、真实本地 SOCKS/VLESS/Trojan 出站及 echo/DNS 观察器，贯通 `刷新 → 选择 → 应用 → Rule 代理 → 原订阅失效/坏更新→保留旧代际`；将忽略的订阅/ISP route 单独断言为零。
4. **MVP-1D**：为选定的 Clash/YAML 或 V2Ray/Base64 入口补齐字段映射/来源报表/拒绝语义；CI 夹具覆盖重复标签、非法 URL、部分坏节点、TLS 字段、极大输入、秘密脱敏和快照原子性。

**MVP-1 退出条件**：普通用户能导入至少一种常见格式、选定可达节点并使真实 Core 经 Rule/Selected 产生可观测流量；出现不支持的节点/来源时给出可理解的错误，且不会应用半成功快照。这项是当前**最短关键路径**，优先于继续增加恢复候选内部微观检查点。

### MVP-2 具体拆分（CN 与五层不可妥协）

1. 对固定来源的 28 组建立字段级映射表：原规则字段、条件组合/否定、来源顺序、启停状态、目标、DNS、地区自动追加及覆盖规则；缺少上游行为证据时标为 blocker，并建立可复现的原版/受控行为夹具。
2. 完成“原始预设 → 用户覆盖 → 五层 RoutingPlan → 完整 source-map → Core 原生配置”确定性生成；不存在的规则资源、GeoIP/ACL 错位、丢失 DNS 绑定均失败关闭，不退化为直连。
3. 收敛 68 个逻辑规则资源引用的来源/哈希/许可，解决缺失的 `geoip:bing` 等问题；不得擅自合成“等效”数据或用没有授权的上游文件发布。**私有用户提供的经校验规则源**可用于内部测试，但不等于具有再分发许可的发行包。
4. 用离线/隔离 Core + 受控 DNS/出站观测构造五层冲突、组 DNS、bootstrap/outbound DNS、FINAL、NONE/BLOCK、负例资源缺失、Custom 引用 GeoIP/ACL 的真实行为回归；验收依赖请求结果，不只比较 JSON。

### MVP-3 具体拆分（TUI）

- 首页显示 Daemon/Core/Applied/LKG、上次更新、离线依赖、配置是否待应用。
- 受保护的来源输入/本地导入、手动刷新、节点列表/搜索/选择；凭据不传入 argv、不回显、不存日志。
- 保留 28 组原始顺序及层级来源、必要 enable/target/DNS 改动、地区追加开关；展示 simulated/unknown/observed 区别。
- 全部写操作有修改前后 Diff、风险提示、确认、CAS 冲突重取、成功后实际 generation/readback；无法读取完整列表或终端过窄时禁用写操作。
- TUI/Unix Socket 断开不能停止托管 Core 或误判应用失败为成功，超时不自动重试已可能生效的操作。

### MVP-4 具体拆分（恢复）

- 首先关闭 #59：在准确进程、系统调用阶段和资源占用下复现偶发 `create_scope`；给出**唯一可信的分类根因**或明确证明并消除多个原因，配确定性回归，禁止用无限重试/放宽权限掩盖。
- 将现有内用 SQLite 一致快照/加密归档/只读 Preflight 变成**有限、显式的用户备份入口**，备份需要可信来源、资源闭包、完整性摘要、容量限制与私有权限。
- 真实恢复先进行隔离的候选准备/验证/审计：确认 Core 版本、加密归档、SQLite 逻辑/Schema、规则路径资源、跨进程锁和代际 CAS；任何不一致直接拒绝。
- 在 disposable VM 中演练真正的目标状态恢复、受控 Core 激活/验证、失败回滚、重复/超时命令以及断电/重启后持久日志与已应用配置一致；旧 LKG 必须在失败时仍可用。
- 没有实证前，不新增对外 `restore`、`rollback` 命令，也不启用自动候选 GC；MVP Beta 必须等受支持的真实恢复路径通过才可宣布。

## 4. PR、测试和进度管理

### 4.1 执行规则

- 本计划首先落到 `feat/m0-m1-foundation` 的独立文档 PR，**不直接修改稳定 `main`**。后续功能每次 PR 只解决一条用户闭环或一个可证明的阻断条件，避免一次 PR 混合导入器、UI、恢复删除权限。
- 在 PR 正文记录关联 MVP 任务编号、`docs/plan.md` T 编号、兼容字段子集、可能发生的失败与回退路径、固定 Core/规则 SHA 和验收证据。
- 合并条件：同一个最终 head 的 Go 规范/编译/Vet/测试、**Race 4/4**、Managed Core Integration、原生 Linux amd64/arm64 Core Provenance 全通过；改动涉及 CN 离线数据时还要通过资源审计；涉及运行行为时增加至少一个真实 Core + 本地受控流量证据。
- Rebase、squash、stacked PR 换基底后必须对**新 head SHA**重新验收；未达到条件保持 Draft。历史通过的 CI 不等于新提交通过。
- 每完成一项任务，更新本文件附录“验收追踪”，只附**真实** commit、PR、CI、日志/校验哈希；绝不预填通过或伪造性能指标。

### 4.2 可并行任务与优先级

| 工作流 | 优先级 | 可与哪些任务并行 | 不能跳过的输入 |
| --- | --- | --- | --- |
| 订阅真实落地闭环 | P0 / 第一位 | CN 许可、#59 定位、TUI 只读层 | 现有 Profile/Declaration/Apply API 契约 |
| CN 条件/规则许可 | P0 / 第一位 | 订阅闭环、TUI 概览 | 原版夹具、完整资源清单及合法来源 |
| TUI 操作 | P0 | 真实流量集成、备份 UI 框架 | 已受保护的 Daemon API |
| #59 定位与恢复安全 | P0 / release-blocking | 订阅与 CN 编码 | 真实故障证据、可重复的 VM 故障注入 |
| 打包与长稳 | P0 | 文档编写、后续非阻断协议 | 以上关键状态全部满足 |

## 5. MVP 统一验收矩阵（全部必过）

每项必须同时记录**输入/步骤、预期结果、实际观察、平台/架构、CI 运行链接、提交 SHA、证据路径**。自动化不能覆盖的断电/用户操作，使用有签名/哈希的手工验收记录；没有证据视为“未完成”。

| MVP ID | 关键验收（对应原 T 编号） | 必须通过的最低可复现标准 |
| --- | --- | --- |
| **MV-01** | 普通用户、双架构、无特权三入口（T01/T13/T17） | 新状态 amd64/arm64 启动 Daemon/TUI/Core，闭合三端口流量；TUI kill/SSH 断连后 Core 仍按用户服务策略运行；不存在 TUN 或路由接管 |
| **MV-02** | 真实订阅到运行 Core（T08/T12/T14/T16） | 至少 sing-box + 一种常见订阅；成功快照经用户确认声明/显式应用进入 Applied；源节点换名/删除/坏更新不破坏绑定；订阅分流剥离为零运行规则 |
| **MV-03** | 五层 CN 真实语义（T02–T07/T11/T26） | 28 组/6 默认、原序/区域追加/用户覆盖逐项一致；L1 规则集与 L3/L4 冲突按来源优先；FINAL、NONE、BLOCK 无隐式旁路；真实 Core 结果与 source-map 一致 |
| **MV-04** | DNS 路径（T10/T22/T26） | Group/Direct/Proxy/Outbound/bootstrap 角色受控 DNS 服务器均有与声明匹配的真实请求/出站回执；DNS 循环/缺失资源失败关闭；不伪造域名解析路径 |
| **MV-05** | TUI 用户闭环（T17/T21） | 普通用户通过 TUI/CLI 导入、刷新、选择、编辑组/DNS、预览/确认应用、观察状态；中断/超时/CAS 冲突/恶意终端字符串安全；不编辑 Core 运行 JSON |
| **MV-06** | 事务与恢复（T14/T15/T19/T23） | 坏配置 Core Check 失败保留 Applied/LKG，真实备份经认证可恢复；在 disposable VM 对恢复/应用中断及重启后 DB、journal、资源、代际、Core 身份与旧有效状态一致；#59 已定位并回归 |
| **MV-07** | 离线与许可（T03/T24） | 两架构离线冷启动完整可运行的用户声明、Core 与全部 CN 规则；不依赖运行时下载；许可、SHA、来源完整且允许分发，不能有缺失/不明资源 |
| **MV-08** | 稳定性初验（T18–T21/T25 子集） | 至少 72 小时混合真实流量/断线/故障/刷新/切换的持续证据，含 1000 次流重连压力与 FD/goroutine/内存曲线；无未解释增长、错误直连或状态损坏。7 天/30 天另属正式稳定版门槛 |
| **MV-09** | 发行文档、可追溯性 | 版本化 amd64/arm64 包与锁定 SBOM/许可证，安装/升级/卸载/备份恢复/runbook，已知协议与不能做的能力清单，运行限制明确；固定提交可复现并通过前述矩阵 |

**终止条件（Fail/No-Go）**：任一 MV-01–09 无证据或失败；任意 DNS/规则静默直连；CN 28 组被简化或资源许可未解决；恢复可能覆盖最后有效状态；仍存在未诊断 #59 或未解释增长；测试只在合成 Core/无真实代理路径通过；公开发行包含未许可资源。此时继续开发，**不发布 MVP**。

## 6. MVP 与正式稳定版的明确边界

MVP Beta 是**能力受限但诚实可用**的发行候选：支持字段子集须与兼容矩阵一致，有明确未支持项、不静默丢弃，不假定全部 Karing 功能均兼容。允许暂缓全部高级协议/订阅提供商兼容、全部自动化与 7d/30d 发布耐久认证；但**不允许**暂缓五层分流、CN 预置正确性、实际 DNS 路径、订阅到生效 Core、恢复一致性、安全/许可证、72h 初期运行证据。

`docs/plan.md` M5 仍要求对正式稳定版完成 T01–T26 全部适用场景和 72h/7d/30d 长稳，不得用本计划的 MV-08 代替正式稳定版试验。若某个延后功能属于 `docs/plan.md` 正式版 P0，必须在公开 MVP 说明中明确“Beta 范围外”，而不是删掉原 P0 定义。

## 7. 第一批实施任务与完成定义

**第一批代码任务优先 MVP-1A（订阅快照 → 已确认声明）**，同时独立开展 CN 资源许可/语义证据和 #59 根因定位。推荐的首批小 PR：

1. `mvp(profile): snapshot-to-declaration confirmed CAS stage` —— 完整输入/预览/确认与拒绝信息，不自动 apply；单元测试 + API 集成。
2. `mvp(integration): imported source → selected node → managed Core` —— 私有受控节点与真实 SOCKS5/HTTP/DNS 回执，验证新/旧代际；必须通过 Core Provenance。
3. `mvp(cn): preset source conditions → five-layer typed IR` —— 28 组和地区追加的字段级夹具，拒绝不能无损表达的规则。
4. `mvp(resources): licensed offline CN closure and integrity gate` —— 完整来源/许可/缺口证据，严禁提前打包未授权数据。
5. `mvp(tui): guarded first-run/import/select/apply flow` —— 用户可完成前述闭环，失败消息安全。
6. `mvp(recovery): real restore acceptance after Issue #59` —— 只有 T15/T23 故障注入证据满足后才开放安全的恢复入口。

完成顺序以依赖为准，**禁止把第 6 项缺乏验收作为“仅标 Beta”来绕过数据安全**。

### 7.1 验收追踪（初始登记，不预设通过）

| 项目 | 当前状态 | 需要补充的证据 |
| --- | --- | --- |
| MV-01 | **部分基础** | 真实全流程两架构无特权安装/用户服务退出实证 |
| MV-02 | **未完成** | 导入 → 提交声明 → 可用 Core 流量与失败更新对照 |
| MV-03 | **未完成** | 28 组原条件完整可执行、五层实际冲突测试 |
| MV-04 | **部分基础** | 与真实 CN 分流联合的 Group/Proxy/Node/Direct DNS 路径 |
| MV-05 | **部分基础** | 新用户零手改 JSON 的 TUI 操作录屏/脚本/回执 |
| MV-06 | **未完成，阻断** | #59 根因、可恢复一致备份与 VM 故障回放 |
| MV-07 | **未完成，阻断** | CN 资源许可、完整离线闭包及双架构交付包 |
| MV-08 | **未完成，阻断** | 72h 混合真实流量与资源曲线 |
| MV-09 | **未完成** | 可复现 MVP Beta 包、许可证/SBOM/runbook |

**下次审查所需资料**：每一 MV 编号对应的 issue/PR、合并 commit、最终 head CI、独立真实 Core 测试记录、测试环境/架构和遗留风险。证据不足保持原状态，不凭补充 ADR 数量或 PR 数量计算进度。

### 7.2 增量实现证据登记（2026-11-08；非 MVP 验收）

本表仅记录已发生的代码整合和待验证工作。原第 5 节 MV-01–09
验收门槛与第 7.1 节 **未完成** 的结论保持不变。

| 工作包 | 状态及确定的提交 | 可追溯证据 | 尚未完成的判定 |
| --- | --- | --- | --- |
| MVP-1A / 1C：首次来源→声明 API | [#107](https://github.com/bbbstyyy/karing-tui-v2/pull/107) 已合并，`cc465334` | [最终 Go CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42440870008)，真实 Core、双架构 Provenance 与 Race 4/4 已检查通过 | 受控 HTTP/Core 流量不等于 CN、常见订阅格式与 MV-02 全通过 |
| MVP-3：首次初始化 CLI | [#108](https://github.com/bbbstyyy/karing-tui-v2/pull/108) 已合并，`bec875c8` | [最终 Go CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42443434490)，Race 4/4、真实 Core 与双架构 Provenance 通过 | 仅显式 `proxy-only-no-cn`，无完整 TUI/CN 用户故事验收 |
| MVP-3：首次初始化 TUI | [#109](https://github.com/bbbstyyy/karing-tui-v2/pull/109) 已合并，`867194fa` | [CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42454855889)；最终换基 Go、Race 4/4、真实 Core/双架构已通过 | CN 28 组与 DNS/TUI 完整操作仍未通过 |
| MVP-1D：VLESS URI TCP/TLS | [#110](https://github.com/bbbstyyy/karing-tui-v2/pull/110) 已合并，`e2493b4c` | [CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42460378751)，Go/Race 4/4/Core/双架构通过 | 只覆盖经明确承认的 VLESS TCP/TLS 严格 URI 字段 |
| MVP-1C：VLESS 真实 TLS/UUID | [#111](https://github.com/bbbstyyy/karing-tui-v2/pull/111) 已合并，`8846e21f` | [CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42465312976)，Go/Race 4/4、真实 TLS Core 与双架构通过 | 只证明本地受控 TCP/TLS 子集，不代表所有运营商/传输层 |
| MVP-1C：Trojan 真实 TLS/密码 | [#112](https://github.com/bbbstyyy/karing-tui-v2/pull/112) 已合并，`6b551e08` | [CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42467976308)，Go/Race 4/4、真实 Trojan Core 与双架构通过 | 不覆盖 WS/gRPC/Reality/UDP |
| MVP-1C：Shadowsocks AEAD TCP | [#113](https://github.com/bbbstyyy/karing-tui-v2/pull/113) 已合并，`1c0bf500` | [CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42476700482)，Go/Race 4/4/真实 Core/双架构全通过 | 其他 SS 算法/UDP/插件仍缺 |
| MVP-1D：Clash YAML | [#114](https://github.com/bbbstyyy/karing-tui-v2/pull/114) 已合并，`29cd29d6` | [CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42479491268)，Go/Race 4/4/真实 Core/双架构/CN 审计全通过 | 仅严格兼容字段子集，不覆盖所有 Clash 扩展或提供商 |

| MVP-2：CN 28 组来源就绪检查 | [#115](https://github.com/bbbstyyy/karing-tui-v2/pull/115) 已合并，`e67b2226` | [最终 CI](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42482089165)：Go/Race 4/4、真实 Core、双架构及 CN 资源审计全通过；28 组字段级来源证据与明确阻断只读 API | `geoip:bing`、规则许可/离线安装及真实 CN 五层 DNS/路由仍缺 |
| MVP-2/3：CN 操作员只读 CLI | [#116](https://github.com/bbbstyyy/karing-tui-v2/pull/116) Draft（本 PR，堆叠在 #115） | 固定来源核验、受限读取、完整列表和伪造就绪拒绝测试；待 CI | 不提供 CN 应用/编辑或授权、不能作为 MV-03/07 完成证据 |

**关键阻断不变**：CN 28 组完整五层真实流量、受许可离线规则集（含
`geoip:bing` 缺口）、CN DNS 路径、真实备份恢复与 #59 根因、
72 小时混合耐久以及双架构无特权交付包，尚未达到 MVP Beta 标准。
不得将上述局部合并或 GitHub Actions 绿色结果自动换算为 MV-02–09 通过。

### 7.3 近期 MVP 用户链路增量证据（2026-11-11；非发布验收）

下表只记录 **已集成的精确 PR/CI** 与**待验收工作**；不变更 MV-01–09 的退出门槛，也不把合成回环流量等同于生产 CN 资源与 DNS、恢复或 72h 证据。

| 工作包 | 确认状态 | 可追溯证据 | 继续阻断事项 |
| --- | --- | --- | --- |
| MVP-1C：订阅刷新后受保护的真实 Core 重绑定 | [#130](https://github.com/bbbstyyy/karing-tui-v2/pull/130) 已合并，`39838772`；最终测试提交 `b8817ae4` | [Go CI/Race 4/4](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42762197966)、[Managed Core](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42762197848)、[双架构 Provenance](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42762198010) 成功 | 只是受控 HTTP 出站与显式 Stage/Apply；不代表完整 TUI、CN Group/Proxy DNS、真实恢复完成 |
| MVP-1C/1D：Clash 订阅移除已选节点时拒绝静默迁移 | [#131](https://github.com/bbbstyyy/karing-tui-v2/pull/131) 已合并，`e51e3749`；最终测试提交 `f9574ffa` | [Go CI/Race 4/4](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42775339493)、[Managed Core](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42775339224)、[双架构 Provenance](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42775339301) 成功 | 证明的是安全拒绝与原 LKG 流量，不包含用户选择替代节点的可用操作 |
| MVP-1A/3：显式选择替代节点并准备声明 | [#132](https://github.com/bbbstyyy/karing-tui-v2/pull/132) 已合并，`5d677c18`；最终测试提交 `759da803` | [Go CI/Race 4/4](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42856217089)、[Managed Core](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42856217127)、[双架构 Provenance](https://github.com/bbbstyyy/karing-tui-v2/actions/runs/42856217082) 成功；真实 Clash/Trojan TLS 测试明确执行 PASS | 仅简单 proxy-only CLI/API 显式迁移；尚无完整 TUI/CN、持久化 CurrentSelected 重绑定，须独立 Core Apply |
| MVP-3：从 TUI Nodes 显式选替代节点后 Preview/Stage | [#133](https://github.com/bbbstyyy/karing-tui-v2/pull/133) Draft，**未合并、未验收** | 当前分支新增 `m` 入口、摘要/节点 ID 回执绑定、窄屏与过期页拒绝测试、ADR 0249；**最终 CI 待核对** | 不迁移复杂 CN 分流或持久选择意图；仍缺普通用户完整操作/真实 Core 首次与离线验收 |

**发布状态不变：Pre-MVP。** 28 组生产 CN Group/Proxy DNS 语义、68 引用许可证/离线资源闭包（含 `geoip:bing`）、Issue #59 真正恢复、72h 混合流量和双架构完整离线发行仍未通过。

---

**一句话目标：让一个普通 Linux 用户真正能够安全地导入订阅、按原样使用 CN 五层分流与 DNS、经 TUI/CLI 选节点并应用到 Core、在重启和故障后保持/恢复有效状态；做到并验证这些，才叫 MVP。**
