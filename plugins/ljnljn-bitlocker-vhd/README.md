# ljnljn-bitlocker-vhd

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.bitlocker-vhd`。

识别 VHD/VHDX 中的 BitLocker 签名与密钥线索。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 单文件 | `ljnljn.bitlocker-vhd.file` | vhd, vhdx |

## 覆盖范围

- VHD 文件尾 512 字节 conectix 签名识别
- VHDX 文件头 vhdxfile 签名识别
- 全文件扫描 BitLocker 引导签名 -FVE-FS-（2D 46 56 45 2D 46 53 2D）并输出绝对偏移
- 只读解析 FVE 元数据块、Windows 7+ 卷头布局与 VMK 条目
- 从 protection type 0x0800 的 VMK 解析恢复密钥 GUID；无法解析时写入 limitations，不猜测

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_bitlocker_vhd_8f3c2a10.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_bitlocker_vhd_8f3c2a10.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

不执行解密，不保证恢复密钥存在。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
