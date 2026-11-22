# 服务器试点

代码与运行数据分别部署。仓库只保存程序、配置模板和测试；服务器环境、上游凭据、成员签发包、实际主机公钥和用量账本均留在受控的运行目录。

## 固定提交

从已审阅的发布代码运行 `bash tools/stage_release.sh 完整提交SHA 新目录`。脚本通过固定的 HTTPS 地址匿名取得指定提交，校验 detached HEAD，不执行仓库内容。失败后不覆盖原目录。保留上一份已经验证的发布目录，试点失败时不要切换当前服务。

## 隔离验收

- `python3 -B tools/run_tests.py` 运行旧接入流程和新发布机制、额度账本的离线回归。
- `tools/pilot_cpa_smoke.py` 在独立 Linux 网络命名空间中启动已校验的官方 CLIProxyAPI v8.0.80 和回环模拟上游，不消费模型额度。模拟走的是 OpenAI-compatible Chat Completions 上游，对外检查 `/v1/models`、`/v1/responses` 和 SSE；未验证原生上游压缩及 Codex Desktop 的完整行为。
- `tools/pilot_budget.py` 只负责虚构额度的事务预扣与结算。取消、断流或缺少最终用量时保留预扣；不能直接将其当作美元账本启用。
- `tools/pilot_member_smoke.py` 在同一隔离网络中启动临时 sshd、成员入口和 CPA。复用开通脚本渲染仅允许本地转发到该成员网关的规则，并用旧打包器生成带主机指纹、独立网关端口和成员令牌的个人包。真实 SSH 客户端按包内配置穿过网关，再验证 JSON、SSE 和超额拒绝。不会修改系统 sshd 配置或创建 Linux 账号；试点密钥、ZIP 和账本由临时目录管理。

在 Linux amd64 上，取得官方 `CLIProxyAPI_8.0.80_linux_amd64_no-plugin.tar.gz` 后，可以运行以下命令。`unshare --net` 需要网络命名空间权限；只在新创建的命名空间内启用回环，不改宿主网络。

```bash
unshare --net -- sh -c 'set -eu; ip link set lo up; exec python3 -B tools/pilot_cpa_smoke.py "$1"' -- /path/to/official-release.tar.gz
unshare --net -- sh -c 'set -eu; ip link set lo up; exec python3 -B tools/pilot_member_smoke.py "$1"' -- /path/to/official-release.tar.gz
```

成员试点使用 Linux 已有的 `nobody` 系统身份和 OpenSSH 服务端，不执行真实客户端安装。测试额度为 10；每次先预扣 6，完整响应后结算 3，所以两次成功后余额是 4，第三次必须返回 HTTP 429，并且不能再触发模拟上游。

## 2026-11-21：开源网关和客户端重试

- `tools/pilot_bifrost_smoke.py` 固定官方 Bifrost HTTP v2.6.0 Linux amd64 二进制的 SHA-256，只在独立、仅有回环的网络命名空间运行。将上述 `unshare` 命令中的脚本换成它，并传入解包后的 `bifrost-http`。使用虚构虚拟密钥、回环上游和本地测试价目，不创建正式服务。8 项机器检查通过：缺少或无效成员凭证被拒绝，正常 JSON/SSE 请求完成，模拟上游 429/503 各只调用一次，预算入账后本地返回 402，未触发上游。另一个关键观察是并发两条请求均在预算入账前放行；**原生虚拟密钥预算不是严格的美元硬上限**。
- `python3 -B tools/test_codex_budget_retry.py --codex /path/to/installed/codex` 用 Codex `0.169.0-alpha.11.1` 隔离运行 10 项。默认配置下普通 402/403 各发 6 次，429 有 `Retry-After` 也可发 6 次。为试点 provider 同时设 `request_max_retries = 0` 和 `stream_max_retries = 0` 后，402、403、429 和 503 各只发一次。验证器不读取用户配置或登录；macOS 测试在回环套接字白名单内运行。没有改变现有客户端模板或正式配置。

保留 OpenSSH 和已验证的成员边界。只有能证明允许的请求在出站前有可靠成本上界，或接受另一种严格且可解释的配额单位，才选定正式限额入口；不把 Bifrost 的事后预算或试点虚构额度宣传为美元硬上限。下一阶段仅使用独立 API 项目的受限 Key，不使用个人登录凭证。

## 每人 $100：受限文本线路

`tools/member_dollar_cap.py` 是尚未正式启用的请求前限额入口。沿用 SQLite `BEGIN IMMEDIATE`/`synchronous=FULL`；同一成员的所有密钥对应同一稳定成员 ID，换密钥不重置预算。以整数 nano-USD 计算：1 美元 = 10 亿 nano-USD，每个成员上限为 `100000000000`，不自动充值或重置。同一成员的并发请求共享一个本机磁盘账本，预扣提交成功后才发出唯一的一次 HTTPS POST。余额不足返回本地 `400 budget_reached`，不带 `Retry-After`，不消耗上游配额。配套客户端配置两层重试均为零；本轮不改现有接入包。

支持的唯一计费请求是全球端点 `api.openai.com/v1/responses`、固定 `gpt-5.4-mini-2026-03-17`、Standard 和基于文本的 JSON/SSE。支持客户端执行的 function/custom 工具定义、工具调用及文本结果、Codex 续聊回放的文本和不解密的 reasoning 项；工具定义和结果计入输入预算。强制 `store=false`、`truncation=disabled`，不接受上游托管工具、图片、文件、服务端续接 ID、后台、Compact、WebSocket 或客户端指价。默认最大输出为 256 token，允许 16–4096。按官方公布上下文 400,000 token 全部以未缓存输入价 $0.75/百万计，输出价 $4.50/百万；预扣范围 $0.300072–$0.318432（64 token 时 $0.300288）。只在可信终态含有可核验的用量、模型和服务档时回收差额；折扣不预支，取消、断流、上游错误和不确定用量保留预扣。这里的美元上限覆盖经这条线路的模型费用，不包括税费、服务器及该项目从其他入口产生的费用，不等同于发票结算。

- 价目 [固定型号](https://developers.openai.com/api/docs/models/gpt-5.4-mini) 与 [Responses 契约](https://developers.openai.com/api/reference/resources/responses/methods/create) 核对到 2026-11-21。代码到 2026-11-29 00:00 UTC 自动拒绝新请求，须重新审核价目后才可更新期限。地域数据驻留、不同服务等级和 OpenAI 项目配置变化均需重新审核。
- 真正上线需有专用项目、受限服务账号 Key、无任何直通上游的 SSH 规则、权限 0700 的本机账本目录及 0600 私有文件。所有 worker 必须共用该账本，不能用独立副本、网络文件系统或可被成员覆盖的路径。备份须使用 SQLite 的一致性快照；回滚只回滚程序，**绝不回滚已经放行请求的账本**。账本丢失、损坏或权限异常要关闭入口并先对账，不建空账本继续。OpenAI [项目硬限制](https://developers.openai.com/api/docs/guides/spend-limits) 有传播延迟，只做第二道保护。
- 离线：`python3 -B tools/test_member_dollar_cap.py -v` 验证恰好 $100 边界的两台网关竞争、断流和取消、密钥轮换，以及上游 429/503 的单次调用。`python3 -B tools/test_codex_member_flow.py --codex /path/to/installed/codex` 使用 macOS 的回环隔离和临时配置，把真实 Codex CLI 接到限额入口与模拟上游，验证工具结果回传、同线程恢复和本地限额拒绝。试点配置关闭多代理、网页搜索和 provider 重试；这不等于 Desktop 打包、真实上游或长对话自动压缩已经验收。
- Linux 假成员全链路：在仓库目录运行 `sudo -n unshare --net -- sh -c 'set -eu; ip link set lo up; exec python3 -B tools/pilot_member_dollar_smoke.py'`。复用开户脚本的 SSH 限制与打包器，在临时环境中连接硬限额服务，验证旧隧道、JSON/SSE、备用端口禁止访问和最后一笔余额的并发拒绝。它使用虚构密钥及模拟上游，不改正式 sshd 或创建正式成员。
- Mac 真后台隔离：`python3 -B tools/test_mac_desktop_member.py --codex /path/to/installed/codex`。生成测试成员的 `--budget-mac` 包，以下游回环端口模拟 SSH 转发的网络出口；在沙箱内运行包的 `prepare` 和正版 `app-server`，测试凭据助手、工具结果、多轮恢复及额度拒绝。该项不操作 GUI、安全组或真实上游；Mac 真机的公网 SSH 和 GUI 交互需分别确认。
- 真实验收计划：专用项目、一个私发测试身份、固定模型、纯文本、最多 64 输出 token、只发一次，不人为制造上游拒绝。验收看真实模型和服务档、终态用量及预扣结算，随后关闭一次性入口。测试不需要烧到 $100，也不用原 A/B 账号的 ChatGPT 登录或订阅。

确认可以产生一次真实费用后，在可信的交互式终端中运行 `python3 -B tools/smoke_member_dollar_cap_live.py --i-authorize-one-paid-request`。仅在无回显提示里输入独立项目的 Key，不通过命令参数、聊天或文件传输。程序不持久化 Key，硬编码一次请求及 $0.300288 预扣上界，只输出验收状态和金额，不自动重发；失败先核对项目用量再决定是否新的验收，不重复运行来追求成功。Mac 运行只验收真实 API 与结算；它不替代从新加坡部署主机的端到端验收。

## 正式接入之前

复用已有 SSH 成员开通和接入包流程，但成员转发目的地必须指向经过验收的限额入口，不能绕过该入口直连 CLIProxyAPI。应先证明正式模型及可用端点的费用上界，验证拒绝超额、计量与取消行为，然后用一个测试身份验证真实 Codex 接入。未经此验收，不开放成员接入、不发包。实际客户端配置及签发材料不属于 GitHub 发布物。

`程序/开通新人.py` 的原有 CLI 仍是旧直连 CPA 模式，不能用来给要求硬限额的成员正式开户。新的测试复用 `restricted_tunnel_policy` 生成的专属 SSH 规则，不向 CPA 添加成员令牌。`程序/打包新人两步接入.py` 的个人包可用 `--server-ip`、`--host-public-key`、`--host-fingerprint` 和 `--gateway-port` 显式指定已核实的接入路线。

### Mac 限额包与新成员预配

- `tools/provision_budget_member.py --help`：在管理员私有状态目录中读取已有账本和成员表，为一个未登记的成员准备独立 SSH 规则、仅本人成员令牌及候选成员表。**该命令只预配，不激活。** 正式激活须核对当前成员表基线、追加同一账本的成员 ID、加载候选成员表并验证 SSH 的有效规则；不覆盖既有身份。网关进程在启动时加载成员表，不宣称支持热更新。
- `程序/打包新人两步接入.py --budget-mac`：只有明确提供专用网关端口、独立核对过的 SSH 主机指纹、主机公钥及对应个人令牌时才产出限额包。拒绝旧 CPA 的 8317 和 Windows 模板。打包和发包是两件事；未验收不得发给成员。
- 新包在 Mac 上用 `prepare` 备份当前配置，`team` 核对本包主机和网关模型之后才切换，`personal` 恢复原配置。原包及 Windows 启动器不受影响。团队模式采用固定的 `sg_team_budget`、HTTP/SSE、零模型请求重试；外部 MCP、网页搜索和多代理仅在团队模式关闭。原始配置若被用户另行修改，不自动覆盖。试点不上线真实模型、不发布私有材料。
