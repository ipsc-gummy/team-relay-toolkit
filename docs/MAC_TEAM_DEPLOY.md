# Mac 队友接入

队友只把自己的 SSH 公钥发给管理员。管理员在新加坡服务器为该公钥开通一个成员账号，再私发对应的 Mac 个人 ZIP。队友把 ZIP 和其中的 `FOR-CODEX.md` 交给自己 Mac 上的 Codex Agent。私钥留在队友的 Mac，OpenAI 项目 Key 留在服务器。

队友先使用[公钥生成说明](../新人接入/两步版/第一步_生成公钥发给管理员.md)的 Mac 部分。收到个人包后，依次运行 `bash 接入.command prepare` 和 `bash 接入.command team`，完整退出并重新打开 Codex，使用新对话。切回时运行 `bash 接入.command personal` 并重新打开 Codex。

## 管理员安装

以下命令从已核对 Git 提交的仓库目录执行。安装使用独立的 `sg-budget-relay.service`、服务账号和本地账本，监听端口为 `127.0.0.1:18322`。成员通过公网 SSH 22 使用受限转发，网关无需添加安全组规则。

```bash
host=$(hostname)
rev=$(git rev-parse HEAD)
test -z "$(git status --porcelain)" || exit 1
python3 -B tools/install_budget_relay.py --expected-hostname "$host" --port 18322 install --repo "$PWD" --commit "$rev"
```

安装后服务保持停用。在可信的交互式 SSH 终端执行下列命令。只本人在无回显提示中输入独立项目的 API Key。程序只发送一次 64 输出 token 上限的验收请求，成功才为服务写入文件和验收记录。

```bash
runuser --user sg-budget-relay -- /usr/bin/python3 -B /opt/sg-budget-relay/current/tools/accept_budget_upstream.py --i-authorize-one-paid-request
```

## 开通及发包

将收到的 `.pub` 文件放在管理员的私有目录。先核对成员公钥指纹和 ECS 主机指纹，再用实际成员值替换下面变量。每名新成员用独立的英文用户名和开通批次名。

```bash
python3 -B tools/enroll_budget_member.py --expected-hostname "$host" --stage "$stage" stage \
  --user "$member" --public-key "$public_key" --fingerprint "$member_fingerprint" \
  --server-ip "$server_ip" --host-fingerprint "$server_fingerprint"
python3 -B tools/enroll_budget_member.py --expected-hostname "$host" --stage "$stage" activate --admin-login "$admin_login"
```

首次激活会启动并启用网关。后续激活会重新加载网关的成员列表，应选在没有正在运行的成员请求时执行。激活成功后只私发 `/var/lib/sg-budget-relay-enrollments/<批次>/member-mac.zip` 给相应队友。公钥生成说明可以发到群里。

每名成员的 100 美元上限覆盖本线路内的模型费用。网关在请求上游前预扣并发请求的最高估算金额，确认上游用量后结算。独立项目的其他消费、服务器费用与税费另计。首发提供固定 GPT-5.4 mini 的文本、流式输出和客户端本地工具。

## 核对与回滚

- `systemctl status sg-budget-relay.service` 应显示预期的唯一网关进程。端口只在 ECS 回环监听。成员用包内 `check` 核对公钥、服务器指纹和模型列表。
- 成员开通失败时，脚本尝试恢复原有成员映射和服务状态，并保留已写入的账本记录。核对回滚结果后，再处理失败的批次。
- 升级与版本回滚使用 `install_budget_relay.py` 的 `upgrade` 或 `rollback`，提供已审计的完整提交 SHA。活动服务在显式提供 `--restart-active` 后才会重启。代码版本回滚保留账本、额度、成员表和项目 Key。
- 当前计价复核期限为北京时间 2026-12-22 08:00。续用前复核公开定价再更新已审计版本。 [模型定价](https://developers.openai.com/api/docs/models/gpt-5.4-mini)
