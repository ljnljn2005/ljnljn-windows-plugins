# ljnljn-qq-setup-log（LPP v2）

从 LPP v1 迁移的腾讯 QQ 安装日志 `qq_setup.log` 时间片段插件。编码判定
（UTF-8/BOM → GBK → 替换字符降级）、`mmdd/hhmmss` 抽取与安装/完成/启动
分类保持原实现。

- 插件 ID：`org.ljnljn.qq-setup-log`
- 分析器：`qq_setup_log`（`files`，扩展名 `log` / `txt`）
- 记录类型：
  - `qqsetup.file`：编码、总行数、时间事件数、无时间片段行数、空行数与限制说明；
  - `qqsetup.event`：行号、字符偏移、时间原文、月日时分秒、分类、全部命中类别、
    原始行（截断 200 字符）与截断前字符数。

日志只有 `mmdd/hhmmss`，没有年份和时区，因此记录保留整数分量与原文，**不生成**
`Timestamp`（否则需要猜测年份/时区）。越界时间值照常保留并写入限制说明；
同一行多个片段各输出一条事件。单文件超过 9999 条事件时按 v1 结果上限拒绝该文件
并告警；超过 16 MiB 或无法读取的文件产生 `RESOURCE_LIMIT` 告警，不会静默返回
空结果。

边界：不补年份、不做时区换算、不推断 QQ 使用时段、不关联安装软件或最近访问
CSV、不校验 `QQ.exe` 版本；仅由标记行（无时间片段）表达的状态不会并入事件。

## 构建与验证

```bash
cargo test --locked
cargo build --release --locked
lc-plugin-host --describe --library target/release/ljnljn_qq_setup_log.dll > schema.json
```

`schema.json` 应列出 `org.ljnljn.qq-setup-log`、`qq_setup_log`、
`qqsetup.file` 与 `qqsetup.event`。

## 安装布局

```text
ljnljn-qq-setup-log/
├── plugin.toml
├── ljnljn_qq_setup_log.dll
├── schema.json
└── locales/{en.toml,zh-CN.toml}
```

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
