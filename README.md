# ljnljn-windows-plugins

Windows 取证插件。本仓库按**平台**组织：一个平台一个仓库，统一使用 git tag 与 GitHub
topic `lovelycarve-plugins`。

包含注册表、USB、回收站、浏览器、便笺、QQ 与 BitLocker 方向；其中 USB 设备历史是 LPP v2 预发布插件。

| 插件 | LPP | 能力 |
| --- | --- | --- |
| `ljnljn-windows-registry` | v1 | 注册表综合：SAM NT hash、最后登录、SID、系统版本、Uninstall、USBSTOR、密码策略 |
| `ljnljn-registry-installdate` | v1 | SOFTWARE hive 的 InstallDate 安装时间 |
| `ljnljn-recyclebin` | v1 | 回收站 $I/$R 元数据与删除时间 |
| `ljnljn-psreadline` | v1 | PowerShell 历史中的 URL 与命中命令 |
| `ljnljn-chromium-history` | v1 | Chrome/Edge 多用户、多 profile 历史统计 |
| `ljnljn-stickynotes-vcpwd` | v1 | 便笺 CSV 中的 VCpwd 凭据 |
| `ljnljn-qq-setup-log` | v1 | QQ 安装日志时间片段 |
| `ljnljn-bitlocker-vhd` | v1 | BitLocker VHD/VHDX 识别与恢复密钥线索 |
| `ljnljn-windows-usb-history` | v2 | Windows USBSTOR 设备历史（LPP v2 预览） |

每个插件是独立 Cargo 工程，共享仓库根目录的 SDK；进入插件目录即可单独测试与构建：

```bash
cd plugins/<插件目录>
cargo test --locked
cargo build --release --locked
```

LPP v2 插件位于 `v2/`，使用 `sdk-v2`；其余 LPP v1 插件使用 `sdk-v1`。
v2 插件需要支持 protocol 2 的 LovelyCarve 构建。

Release 提供各插件的 `.lcpkg`、完整平台包与 `SHA256SUMS.txt`。也可以手动把
`plugin.toml`、DLL（v2 还包括 `schema.json` 与 `locales/`）放进插件包目录后重启
LovelyCarve。

插件只读检材，不执行检材内容，不访问网络。源码采用 AGPL-3.0-only。
