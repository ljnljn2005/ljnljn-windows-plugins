# ljnljn-chromium-history

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.chromium-history`。

统计 Chrome/Edge 多用户、多 profile 的 URL 访问与标题。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 整份检材 | `ljnljn.chromium-history` | — |
| 单文件 | `ljnljn.chromium-history.file` | — |

## 覆盖范围

- Chrome 与 Edge 历史访问统计

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_chromium_history.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_chromium_history.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

只读主 History 数据库，未合并 WAL；标题取当前 urls.title。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
