# ljnljn-psreadline

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.psreadline`。

从多用户 PowerShell 历史提取字面 HTTP/HTTPS URL 与含 URL 的命令数。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 整份检材 | `ljnljn.psreadline.urls` | — |
| 单文件 | `ljnljn.psreadline.urls.file` | txt |

## 覆盖范围

- PowerShell历史URL

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_psreadline.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_psreadline.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

历史记录不能证明命令已执行或请求成功。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
