# ljnljn-windows-registry

LovelyCarve **LPP v2** 插件：Windows 注册表取证。保留 v1 的五个独立能力，并按 LPP v2
拆成独立分析器与记录类型：

- SAM 账号、NT/LM 哈希、最后登录、登录次数与 SID（SAM + SYSTEM 配对）
- SOFTWARE 系统版本
- Uninstall 安装项
- USBSTOR 设备与实例
- SAM 密码策略（`MaxPasswordAge`）

- 插件 ID：`org.ljnljn.windows-registry`
- 版本：`0.1.0`，协议 `2`
- SDK：`lovelycarve-plugin 0.2.0`
- 记录类型：`windows.sam.account`、`windows.sam.bootkey`、
  `windows.software.version`、`windows.registry.uninstall`、
  `windows.registry.usbstor`、`windows.registry.policy`

## 分析器

| ID | 作用域 | 输入 | 能力 |
| --- | --- | --- | --- |
| `sam_accounts` | `evidence` | SAM + SYSTEM（每卷） | 按卷配对，派生 bootkey 并提取账号哈希 |
| `sam_accounts_system` | `system`（`windows`） | `Windows/System32/config/SAM`、`.../SYSTEM` | 当前系统上的同一流程 |
| `software_version` | `system`（`windows`） | `.../SOFTWARE` | CurrentVersion 版本值 |
| `software_version_file` | `files` | 选中 hive | 单 hive 版本 |
| `uninstall` | `system`（`windows`） | `.../SOFTWARE` | Uninstall 安装项 |
| `uninstall_file` | `files` | 选中 hive | 单 hive Uninstall |
| `usbstor` | `system`（`windows`） | `.../SYSTEM` | USBSTOR 设备与实例 |
| `usbstor_file` | `files` | 选中 hive | 单 hive USBSTOR |
| `password_policy` | `system`（`windows`） | `.../SAM` | MaxPasswordAge |
| `password_policy_file` | `files` | 选中 hive | 单 hive 策略 |

SAM 分析器按输入文件的卷键（`FileRef::root`）配对：同一卷上的 `SAM` 与 `SYSTEM`
才组合；证据作用域一次运行即可覆盖全部卷。缺少任一份 hive 时按卷产生明确告警。

## 记录

### `windows.sam.account`

- 账号名、RID、SID（`Names` 默认值可解析时拼成 `S-1-5-21-a-b-c-RID`）、用户键与路径
- **`nt_hash` / `lm_hash` 是 `hash` 字段，内容只有小写十六进制 MD4**，绝不含明文口令
- `nt_state` / `lm_state`：`present` / `zero_placeholder` / `unavailable` / `not_saved`，
  并附 `nt_reason` / `lm_reason`。全零占位、LM 未保存、FakeBootKey 缺失或 AAD 校验
  失败都明确标注，不用猜测值填充
- `hash_algorithm`（`nt` / `lm` / `none`）、登录次数、最后登录（FILETIME → UTC，
  时间线角色 `login`）与原始 FILETIME
- 解密校验、解密原因、F 值 RID、NT/LM 偏移与长度、逐账号限制说明
- 每条记录同时带 SAM 与 SYSTEM 两个来源，便于复核 bootkey 与密文

### `windows.sam.bootkey`

从 SYSTEM `Lsa` 的 `JD`/`Skew1`/`GBG`/`Data` 类名派生的 16 字节 bootkey、置换前
数据、实际 Lsa 路径、每个类名及其 cell 偏移，以及 FakeBootKey/用户键失败等限制。

### `windows.software.version`

`ProductName`、`CurrentVersion`、`CurrentBuild`、`CurrentBuildNumber`、`CSDVersion`、
`BuildLabEx`、`InstallDate` 原值。只读，不推断版本含义。

### `windows.registry.uninstall`

DisplayName（键字段）、安装项键、DisplayVersion、Publisher、InstallDate 原值
（字符串按原样保留，不当作时间）、InstallLocation、键最后写入（FILETIME → UTC）、
WOW6432Node 标记。没有 DisplayName 的子键跳过并在摘要计数。

### `windows.registry.usbstor`

设备键、实例键、FriendlyName、DeviceDesc、Service、ContainerID、HardwareID、
首次安装与最后接入（设备属性 `0064`/`0066`，存在才输出）、设备键与实例键最后写入
（FILETIME → UTC）。无实例键的设备也输出一行（实例为空，标题为设备键）。

### `windows.registry.policy`

`Domains\Account\F` 偏移 0x20 的 `MaxPasswordAge`：原始 100ns、秒、天与状态
（`set` / `never_or_unset`）。

## 时间语义

- FILETIME（1601 起 100ns）只在有效时输出 UTC；键最后写入、最后登录、安装/接入时间
  都是这一类。
- Uninstall 的 `InstallDate` 是字符串原值（常见 `YYYYMMDD`），不解释为时间。
- 不读取本机时区，不做本地时间推断。

## 解析与边界

- 复用 v1 的 regf / bootkey / SAM / 密码学解析器，所有 cell 访问都有边界检查；
  bootkey 置换表、RC4/AES-128-CBC、MD4/MD5 均有公开测试向量。
- **修正 base block 偏移**：v1 `windows-registry`/v2 USB 参考实现的 regf 解析器按
  `0x34/0x38` 读取根键与 hbin 长度，而真实 REGF 头是 `0x14/0x18` 版本、
  `0x24/0x28` 根键与 hbin 长度（已用本机真实 hive 头核对）。本插件及其合成 hive
  使用真实偏移，否则真实 hive 会以“hbin 长度 0”被拒。
- 同一解析器还修正了：hbin 偏移字段以首个 hbin 为 0（不是文件绝对偏移）；cell 只有
  起点 4 字节长度，末尾 4 字节属于载荷（不再要求“起止长度相等”）；子键列表
  `lf/lh/li/ri` 签名按小端读取；大值 `db` 两字节签名；内联值起点按 vk 的 `name_len` 字节数（非字符数）。合成 hive 构造器同步修正，
  并用仓库内真实 hive 夹具验证了头部、hbin、根键与子键列表可解析。
- 每个 hive 上限 1 GiB；清单声明 2 GiB 进程内存。单文件分析器接受任意选中的 hive；
  键不匹配时输出告警而不是空成功。
- 不做口令破解、字典、彩虹表或在线攻击；不解析 NTDS.dit、域缓存或 DPAPI。
- 证据作用域只匹配 `Windows/System32/config/{SAM,SYSTEM}`；其它路径用文件分析器。

## 与 v1 的能力对照

| v1 能力 | v2 |
| --- | --- |
| evidence SAM+SYSTEM 配对 | `sam_accounts`（按卷配对） |
| 文件级 software-version / uninstall / usbstor / sam-policy | `*_file` 分析器 |
| bootkey、账号、NT/LM 哈希、SID、最后登录 | `windows.sam.account` / `windows.sam.bootkey` |
| SOFTWARE 版本 | `windows.software.version` |
| Uninstall（含 WOW6432Node） | `windows.registry.uninstall` |
| USBSTOR 设备与实例 | `windows.registry.usbstor` |
| MaxPasswordAge | `windows.registry.policy` |
| 逐条限制说明 | 账号/ bootkey 记录的 `limitations` 列表 + 告警 |

未保留：v1 的 `AnalysisResult` 汇总文本格式与 `ResultNode` 列定义（由 v2 记录结构
取代）；没有丢弃任何取证字段。

## 构建与测试

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物：`target/release/ljnljn_windows_registry.dll`。

插件包目录：

```text
ljnljn-windows-registry/
├── plugin.toml
├── ljnljn_windows_registry.dll
├── schema.json
└── locales/{en,zh-CN}.toml
```

`schema.json` 由 `lc-plugin-host --describe --library <dll>` 生成。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
