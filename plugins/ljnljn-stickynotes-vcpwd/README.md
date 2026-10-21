# ljnljn-stickynotes-vcpwd（LPP v2）

从 LPP v1 迁移的便笺（Sticky Notes）CSV/TSV 凭据提取插件。字符集识别、
分隔符判定、CSV 引号规则和 `VCpwd` 抽取保持原实现。

- 插件 ID：`org.ljnljn.stickynotes-vcpwd`
- 分析器：`stickynotes_vcpwd`（`files`，扩展名 `csv` / `tsv` / `txt`）
- 记录类型：
  - `stickynotes.file`：编码、分隔符、记录数、凭据值数、未解析行数、限制说明；
  - `stickynotes.credential`：凭据值（去重）、原始单元格、行号、列名/列序号、
    出现次数与其余出现位置、截断标记。

值只来自本次检材字节：`VCpwd` 键名不区分大小写，支持 `:`、`=`、`：`。
超过 16 MiB 的文件按 v1 语义解析前 16 MiB，并同时产生 `INPUT_TRUNCATED`
告警和限制说明；短读、无法读取的文件产生告警，不会静默返回空结果。

边界：不实现 VeraCrypt 解密挂载，不校验密码正确性，不统计卷内文件数量，
不跨文件合并凭据，不把未做的事写成已做。记录不含时间戳——抽取到的便笺内容
没有可靠时间语义。

## 构建与验证

```bash
cargo test --locked
cargo build --release --locked
lc-plugin-host --describe --library target/release/ljnljn_stickynotes_vcpwd.dll > schema.json
```

`schema.json` 应列出 `org.ljnljn.stickynotes-vcpwd`、`stickynotes_vcpwd`、
`stickynotes.file` 与 `stickynotes.credential`。

## 安装布局

```text
ljnljn-stickynotes-vcpwd/
├── plugin.toml
├── ljnljn_stickynotes_vcpwd.dll
├── schema.json
└── locales/{en.toml,zh-CN.toml}
```

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
