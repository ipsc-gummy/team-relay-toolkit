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

## 正式接入之前

复用已有 SSH 成员开通和接入包流程，但成员转发目的地必须指向经过验收的限额入口，不能绕过该入口直连 CLIProxyAPI。应先证明正式模型及可用端点的费用上界，验证拒绝超额、计量与取消行为，然后用一个测试身份验证真实 Codex 接入。未经此验收，不开放成员接入、不发包。实际客户端配置及签发材料不属于 GitHub 发布物。

`程序/开通新人.py` 的原有 CLI 仍是旧直连 CPA 模式，不能用来给要求硬限额的成员正式开户。新的测试复用 `restricted_tunnel_policy` 生成的专属 SSH 规则，不向 CPA 添加成员令牌。`程序/打包新人两步接入.py` 的个人包可用 `--server-ip`、`--host-public-key`、`--host-fingerprint` 和 `--gateway-port` 显式指定已核实的接入路线。
