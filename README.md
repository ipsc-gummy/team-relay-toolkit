# Team Relay Toolkit

基于 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的团队模型接入与运维工具。这个仓库保存脱敏后的自编工程层，展示成员接入、客户端路由、配置自愈和用量统计的实现。

项目来自真实团队部署，也保留了实际使用中发现的边界：客户端更新、Windows 沙箱、私钥解锁和网络中断仍需要本机验收。这里的隔离测试不等同于所有平台、所有 App 版本都已通过验证。

## 功能与贡献边界

| 模块 | 本仓库实现 | 依赖的上游能力 |
|---|---|---|
| 成员管理 | 受限账号开通、个人接入包、身份核对 | Linux / OpenSSH |
| 客户端接入 | team / personal / other 切换、认证助手、隧道生命周期管理 | Codex App / CLI、OpenSSH |
| App 路由 | 在 app-server 协议层处理新建、恢复、分叉任务的 provider | 官方 app-server 协议 |
| 配置自愈 | 受管字段、canonical provider、协议兼容检查、原子替换与回滚 | TOML、操作系统文件接口 |
| 用量统计 | 按成员归属、去重、SQLite 持久化、本人查询 | CLIProxyAPI 提供的用量事件 |

OAuth 登录与刷新、上游模型访问和 Responses API 转发由 CLIProxyAPI 完成，不属于本仓库原创实现。本仓库不捆绑或修改 CLIProxyAPI 核心二进制。

## 最小架构

```text
Codex App / CLI
  → 本机认证助手与 SSH 隧道
  → 服务器回环地址上的 CLIProxyAPI
  → 已配置的上游模型服务

CLIProxyAPI 用量队列
  → 自编统计服务
  → SQLite
  → 按服务器身份查询本人报告
```

## 目录

```text
程序/
  App切换/                  客户端配置、认证助手和隧道维护
  新人一键接入/            安装与修复入口
  App全局路由.py           管理员 Mac 路由控制器
  App全局路由代理.py       app-server 协议代理
  App自愈.py               受管字段自愈与事务
  用量统计/                独立统计服务与部署脚本
  开通新人.py              服务器受限成员开通
  打包新人两步接入.py      按白名单生成接入包
新人接入/                  脱敏后的两步说明模板
docs/                      架构、发布边界和验证说明
tools/                     隔离测试与发布检查
licenses/                  第三方许可证
```

保留原来的中文文件名与目录，便于对照部署实现。正式服务器、成员包、个人凭据、用量数据库、运行日志和历史配置快照均不在仓库中。

## 先运行离线测试

使用 Python 3.11 或更高版本：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -B tools/check_release.py
python -B tools/run_tests.py
```

Windows 可使用 `.venv\Scripts\Activate.ps1` 激活虚拟环境。完整隔离回归以 macOS / Linux 的结果为准，Windows 上的真实 App、ACL、沙箱与重连另行验收。

这些测试使用临时目录、虚拟凭据及替身接口，不需要现有服务器和个人 Pro 登录，也不应生成真实模型请求。

本次发布副本已运行 250 项隔离测试：247 通过、3 明确跳过、0 失败。范围和跳过原因见 [验证记录](docs/VALIDATION.md)。

## 配置与部署范围

这是工程源码与部署模板，不包含现成可用的团队服务。`203.0.113.10` 和 `relay.example.invalid` 是示例地址，公钥及指纹使用公开测试向量，不能直接用于真实服务器身份校验。

部署前需要管理员配置真实服务地址、可信主机指纹、成员公钥及合法可用的上游认证。依赖包和部署入口见 [部署说明](docs/DEPLOYMENT.md)。个人包应只交付给对应成员；仓库中的默认参数不会连接原部署环境。

## 已知边界

- Windows 的原生桌面、运行身份、SSH agent、ACL 和 App 沙箱需要在收件人电脑上验证。宿主机 PowerShell 的联网结果与 Agent 沙箱内结果不能相互替代。
- 普通成员包与管理员全局路由代理不是同一个产品入口，不能承诺切换全局配置就迁移全部旧任务。
- 自动重连不能修复持续网络阻断、失效凭据或不兼容协议；未知端口占用必须停下核对。
- 统计只能覆盖经过本中转的请求。显示的 Cost 是参考折算，含项目自定义的统一口径，不是扣费记录或官方剩余额度；未知模型可能使用默认参考价。
- 用量队列读取与持久化之间存在故障窗口，当前不提供严格计费账本、个人硬限额或财务级完整性保证。

## 许可与来源

本仓库自编部分以 MIT 许可证发布，见 [LICENSE](LICENSE)。CLIProxyAPI 的原版权与 MIT 许可声明单独保留在 [licenses/CLIProxyAPI-MIT.txt](licenses/CLIProxyAPI-MIT.txt)，详见 [第三方说明](THIRD_PARTY_NOTICES.md)。

许可证只说明代码使用权；实际部署还需要遵守所接入服务的条款。项目以工具工程、可靠性机制和可复现测试为贡献范围，不声称基础代理协议或上游模型能力为原创。
