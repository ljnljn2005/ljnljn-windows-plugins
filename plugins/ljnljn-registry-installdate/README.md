# ljnljn-registry-installdate

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.registry-installdate`。

解析 SOFTWARE hive 中的 InstallDate，支持单文件与整份检材。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 单文件 | `ljnljn.registry-installdate.file` | — |
| 整份检材 | `ljnljn.registry-installdate.evidence` | — |

## 覆盖范围

- regf 头部校验（版本 / 根键偏移 / hive bins 长度 / 校验和）
- Microsoft\Windows NT\CurrentVersion 路径查找（键名大小写不敏感）
- InstallDate 原值类型与原值（REG_DWORD / 十进制 REG_SZ）
- Unix 秒 → UTC ISO8601 换算（不推断本地时区）
- ProductName / CurrentBuild / CurrentVersion 等辅助值（存在才输出）
- 解析告警、覆盖范围与限制说明

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_registry_installdate_bf1bcabf.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_registry_installdate_bf1bcabf.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

只读取注册表值，不推断未声明的安装行为。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
