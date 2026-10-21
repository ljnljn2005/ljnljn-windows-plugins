# ljnljn-windows-plugins

Windows 取证插件，全部使用 LovelyCarve **LPP v2**（protocol 2）与类型化记录。
统一 git tag 与 GitHub topic：`lovelycarve-plugins`。

| 插件 | LPP | 能力 |
| --- | --- | --- |
| `ljnljn-windows-registry` | v2 | 注册表综合：SAM 账户与 NT hash、系统版本、Uninstall、USBSTOR、密码策略 |
| `ljnljn-registry-installdate` | v2 | SOFTWARE hive InstallDate 安装时间 |
| `ljnljn-recyclebin` | v2 | 回收站 $I/$R 元数据与删除时间 |
| `ljnljn-psreadline` | v2 | PowerShell 历史 URL 与命中命令 |
| `ljnljn-chromium-history` | v2 | Chrome/Edge 多用户、多 profile 历史统计 |
| `ljnljn-stickynotes-vcpwd` | v2 | 便笺 CSV 中的 VCpwd 凭据 |
| `ljnljn-qq-setup-log` | v2 | QQ 安装日志时间片段 |
| `ljnljn-bitlocker-vhd` | v2 | BitLocker VHD/VHDX 识别与恢复密钥线索 |
| `ljnljn-windows-usb-history` | v2 | Windows USBSTOR 设备与实例历史 |

每个插件是独立 Cargo 工程，仓库根目录提供共享 SDK v2：

```bash
cd plugins/<插件目录>
cargo test --locked
cargo build --release --locked
```

Release 提供各插件 `.lcpkg`、完整平台 zip、`INDEX.json` 和
`SHA256SUMS.txt`。插件只读检材，不执行检材内容，不访问网络；结果需要
取证员复核。源码采用 AGPL-3.0-only。
