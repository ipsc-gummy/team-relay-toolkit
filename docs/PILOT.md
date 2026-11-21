# 服务器试点

代码与运行数据分别部署。仓库只保存程序、配置模板和测试；服务器环境、上游凭据、成员签发包、实际主机公钥和用量账本均留在受控的运行目录。

## 固定提交

从已审阅的发布代码运行 `bash tools/stage_release.sh 完整提交SHA 新目录`。脚本通过固定的 HTTPS 地址匿名取得指定提交，校验 detached HEAD，不执行仓库内容。失败后不覆盖原目录。保留上一份已经验证的发布目录，试点失败时不要切换当前服务。

## 隔离验收

- `python3 -B tools/run_tests.py` 运行旧接入流程和新发布机制、额度账本的离线回归。
- `tools/pilot_cpa_smoke.py` 在独立 Linux 网络命名空间中启动已校验的官方 CLIProxyAPI v8.0.80 和回环模拟上游，不消费模型额度。模拟走的是 OpenAI-compatible Chat Completions 上游，对外检查 `/v1/models`、`/v1/responses` 和 SSE；未验证原生上游压缩及 Codex Desktop 的完整行为。
- `tools/pilot_budget.py` 只负责虚构额度的事务预扣与结算。取消、断流或缺少最终用量时保留预扣；不能直接将其当作美元账本启用。

在 Linux amd64 上，取得官方 `CLIProxyAPI_8.0.80_linux_amd64_no-plugin.tar.gz` 后，可以运行以下命令。`unshare --net` 需要网络命名空间权限；只在新创建的命名空间内启用回环，不改宿主网络。

```bash
unshare --net -- sh -c 'set -eu; ip link set lo up; exec python3 -B tools/pilot_cpa_smoke.py "$1"' -- /path/to/official-release.tar.gz
```

## 正式接入之前

复用已有 SSH 成员开通和接入包流程，但成员转发目的地必须指向经过验收的限额入口，不能绕过该入口直连 CLIProxyAPI。应先证明正式模型及可用端点的费用上界，验证拒绝超额、计量与取消行为，然后用一个测试身份验证真实 Codex 接入。未经此验收，不开放成员接入、不发包。实际客户端配置及签发材料不属于 GitHub 发布物。
