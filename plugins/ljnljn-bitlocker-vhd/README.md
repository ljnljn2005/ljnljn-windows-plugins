# ljnljn-bitlocker-vhd（LPP v2）

从 LPP v1 迁移的 BitLocker VHD/VHDX 识别插件。VHD footer / VHDX 头识别、
`-FVE-FS-` 签名扫描、Windows 7+ FVE 卷头解析与独立元数据块回退均沿用原解析器。

- 插件 ID：`org.ljnljn.bitlocker-vhd`
- 分析器：`bitlocker_vhd`（`files`，扩展名 `vhd` / `vhdx`）
- 记录类型：
  - `bitlocker.image`：格式、文件大小、是否命中签名、签名数、恢复密钥 GUID 列表、
    扫描范围/截断、VHD/VHDX 元数据与限制说明；
  - `bitlocker.hit`：每个 `-FVE-FS-` 的绝对偏移、卷头偏移、引导入口、解析状态/
    依据、FVE 元数据字段、VMK 数与错误；
  - `bitlocker.vmk`：每个 VMK 的 GUID、protection type、是否恢复密码保护。

恢复密钥 GUID 只取 protection type `0x0800` 的 VMK 标识符；找不到时留空并写入
限制说明，不猜测。扫描上限 8 GiB、最多 64 个命中；扫描被截断或超限会产生
`SCAN_TRUNCATED` / `SIGNATURE_HIT_LIMIT` 告警，短读或扫描失败也会告警，不会
静默返回成功。

边界：不解密、不挂载、不执行镜像内容，不提取 48 位恢复密钥数字密码；不解析
分区表、动态块 BAT、差异盘链与校验和；不解析 Vista 卷头、BitLocker To Go FAT；
不从外部恢复密钥文件、注册表或文件名推断 GUID。

## 构建与验证

```bash
cargo test --locked
cargo build --release --locked
lc-plugin-host --describe --library target/release/ljnljn_bitlocker_vhd.dll > schema.json
```

`schema.json` 应列出 `org.ljnljn.bitlocker-vhd`、`bitlocker_vhd` 以及
`bitlocker.image`、`bitlocker.hit`、`bitlocker.vmk`。

## 安装布局

```text
ljnljn-bitlocker-vhd/
├── plugin.toml
├── ljnljn_bitlocker_vhd.dll
├── schema.json
└── locales/{en.toml,zh-CN.toml}
```

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
