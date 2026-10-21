# ljnljn-recyclebin

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.recyclebin`。

解析 $I v1/v2 原始名称、路径、大小与删除时间，检材模式检查 $R 配对。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 单文件 | `ljnljn.recyclebin.file` | — |
| 整份检材 | `ljnljn.recyclebin.evidence` | — |

## 覆盖范围

- 回收站文件名
- 删除时间
- 原始大小
- 回收站内容配对

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_recyclebin.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_recyclebin.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

首版不恢复文件内容，不核验第三方 CSV。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
