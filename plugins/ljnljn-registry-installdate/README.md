# ljnljn-registry-installdate

LovelyCarve **LPP v2** 插件：从 Windows `SOFTWARE`（或任意 regf 主 hive）读取
`Microsoft\Windows NT\CurrentVersion\InstallDate`，输出原值、原始字节、UTC 时间与
可信度分级。

- 插件 ID：`org.ljnljn.registry-installdate`
- 版本：`0.1.0`，协议 `2`
- SDK：`lovelycarve-plugin 0.2.0`
- 记录类型：`windows.installdate.hive`、`windows.installdate.key`、
  `windows.installdate.value`、`windows.installdate.aux`、
  `windows.installdate.limitation`

## 分析器

| ID | 作用域 | 输入 | 用途 |
| --- | --- | --- | --- |
| `installdate` | `system`（`windows`） | `Windows/System32/config/SOFTWARE` | 当前识别的 Windows 系统 |
| `installdate_evidence` | `evidence` | `Windows/System32/config/SOFTWARE`（每个卷） | 整体检材，逐卷查找 |
| `installdate_file` | `files` | 用户选中的 regf 文件 | 已提取的 SOFTWARE 或其它 hive |

三个分析器共用同一实现：`run.inputs()` 里的每个文件都按同一流程解析。

## 记录

- **`windows.installdate.hive`**：base block 结论——regf 版本、根键偏移、hbin 长度、
  校验和（存储值/计算值）与状态（`match` / `mismatch` / `placeholder_zero` /
  `not_checked`）、序列号、文件类型/格式、头部最后写入（FILETIME → UTC）、错误码。
- **`windows.installdate.key`**：目标键是否存在、实际大小写路径、第一个缺失路径段、
  cell/文件偏移、键最后写入、值数量与值名。键名大小写不敏感。
- **`windows.installdate.value`**：`InstallDate` 的状态（`parsed` / `missing` /
  `unusable`）、原值类型与类型号、原值、原始字节、`0x` 十六进制、UTC、原样表示、
  可信度（`zero` / `plausible` / `implausible` / `unrepresentable`）、值节点与数据
  cell 偏移、内联/大值标记、判定说明。缺失时也输出记录，避免静默成功。
- **`windows.installdate.aux`**：存在才输出的只读辅助值（`ProductName`、
  `CurrentBuild`、`CurrentVersion`、`UBR`、`EditionID` 等 12 项）及其值类型与 cell。
- **`windows.installdate.limitation`**：固定的 8 条覆盖范围与限制说明，作为一条
  带 `items` 列表的记录保留（v1 的 8 条 limitation artifact 合并为一条）。

## 时间语义

- `InstallDate` 只按 **Unix 秒 → UTC** 解释；不推断本地时区，原样表示固定标注
  “本地时区未知”。
- `0` 视为“未写入”，保留原值但不给出时间。
- 落在 2000-01-01 ~ 2100-01-01 之外的值仍换算 UTC，但标为 `implausible` 且状态为
  `unusable`；超过 9999 年的值标为 `unrepresentable`，不给 UTC。
- 头部与键时间的 FILETIME 只在有效时输出 UTC。
- `REG_DWORD_BIG_ENDIAN`、`REG_QWORD`、`REG_BINARY` 等类型只保留原始字节。

## 解析与边界

- 复用仓库内已测试的 regf 只读解析器（与 windows-registry / usbstor 分析器同源），
  所有 cell 访问都有边界检查；本插件只额外读取 base block 字段与校验和。
- 复用前修正了该解析器与真实 REGF 布局的偏差（已用真实 hive 头与本地 hive 夹具核对）：
  base block 版本 `0x14/0x18`、根键 `0x24`、hbin 长度 `0x28`；hbin 偏移字段以首个
  hbin 为 0；cell 只有起点 4 字节长度（末尾 4 字节属于载荷）；子键列表签名
  `lf/lh/li/ri` 按小端读取；大值 `db` 分段签名按两字节读取；内联值起点按 vk 的 `name_len` 字节数。
- base block 的魔数/版本/文件类型/hbins 长度/根键偏移是解析闸门；校验和不一致会
  告警（`HEADER_CHECKSUM_MISMATCH`）但仍按结构解析，因为解析器自身有完整边界检查。
- 校验和为 0 表示 Windows 未写入，按规范接受并标记 `placeholder_zero`。
- 每个输入上限 1 GiB；清单声明 2 GiB 进程内存。
- 不解析 `.LOG1`/`.LOG2` 事务日志，不做安装日志交叉验证，不做年份/时区猜测；
  其它路径的 hive 请用 `installdate_file` 单独选择。
- 文件无法读取、hive 不合法、目标键/值缺失、值类型不支持都会产生运行告警，
  不会返回“空成功”。

## 构建与测试

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物：`target/release/ljnljn_registry_installdate.dll`。

插件包目录：

```text
ljnljn-registry-installdate/
├── plugin.toml
├── ljnljn_registry_installdate.dll
├── schema.json
└── locales/{en,zh-CN}.toml
```

`schema.json` 由 `lc-plugin-host --describe --library <dll>` 生成。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
