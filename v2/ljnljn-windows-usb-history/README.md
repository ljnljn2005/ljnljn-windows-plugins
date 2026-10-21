# ljnljn-windows-usb-history

LovelyCarve **LPP v2** 原生插件（pre-release），从 Windows `SYSTEM` hive 的
`Enum\USBSTOR` 提取 USB 存储设备与实例历史。

- 插件 ID：`org.ljnljn.windows-usb-history`
- 版本：`0.1.0`
- SDK：`lovelycarve-plugin 0.2.0`（LPP v2）
- 作用域：`system`，平台 `windows`
- 输入：`Windows/System32/config/SYSTEM`
- 分析器：`usbstor`
- 记录类型：`windows.usb.device`

## 提取内容

每条 USBSTOR 实例记录包含：

- 设备键与实例键
- 设备名称、设备描述、驱动服务、容器 ID、硬件 ID
- 首次安装时间与最后接入时间（读取设备属性 `0064` / `0066`，存在时）
- 设备键与实例键的注册表最后写入时间（作为时间线事件）

记录来源直接指向 SYSTEM hive，界面可据此定位源文件。

## 构建与测试

仓库内置 LovelyCarve SDK 0.2.0（`vendor/lovelycarve-sdk`）：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_windows_usb_history.dll`。

## 安装

插件包目录需要包含：

```text
ljnljn-windows-usb-history/
├── plugin.toml
├── ljnljn_windows_usb_history.dll
├── schema.json
└── locales/
    ├── en.toml
    └── zh-CN.toml
```

Release 中的 `.lcpkg` 可直接通过 LovelyCarve「设置 → 插件」安装；也可以手动放入
插件目录后重启 LovelyCarve。运行时选择 Windows 系统，执行「USB 存储设备历史」。

## 边界

- 只解析 SYSTEM hive 中的 `Enum\USBSTOR`，不解析 setupapi 日志、不枚举非存储 USB 设备。
- 首次安装/最后接入依赖设备属性；属性缺失时字段为空，不猜测。
- 注册表键最后写入时间是 hive 中的键时间，不等同于设备实际插拔时间。
- 插件只读检材，不执行检材内容，不访问网络。
- 这是使用新 SDK 的 pre-release，已通过单元测试、release 构建和 v2 宿主
  `--describe` 校验，尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证。
