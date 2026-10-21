# ljnljn-windows-registry

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.windows-registry`。

解析 SAM/SOFTWARE/SYSTEM hive：NT hash、最后登录、SID、系统版本、Uninstall、USBSTOR 与密码策略。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 整份检材 | `ljnljn.windows-registry` | — |
| 单文件 | `ljnljn.windows-registry.software-version` | hive, dat |
| 单文件 | `ljnljn.windows-registry.uninstall` | hive, dat |
| 单文件 | `ljnljn.windows-registry.usbstor` | hive, dat |
| 单文件 | `ljnljn.windows-registry.sam-policy` | hive, dat |

## 覆盖范围

- 注册表 hive 来源
- bootkey 派生(JD/Skew1/GBG/Data)
- 账号与 RID
- NT/LM 哈希提取
- SOFTWARE 系统版本
- Uninstall 安装项
- SYSTEM USBSTOR 设备与实例

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_sam_hive_hash_extract_da5e5db1.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_sam_hive_hash_extract_da5e5db1.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

NT hash 不是明文口令；零哈希/不可解密账户会明确标记。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
