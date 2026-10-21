# ljnljn-recyclebin（LPP v2）

Windows Vista+ 回收站 `$I` 元数据插件，从 LPP v1 迁移到 SDK 0.2.0 / protocol 2。
解析逻辑沿用原插件的严格 `$I` v1/v2 解析器。

- 插件 ID：`org.ljnljn.recyclebin`
- 记录类型：`windows.recyclebin.entry`
- `recyclebin_files`（`files`）：用户选中的 `$I` 文件；不限制扩展名，因为 `$I`
  文件名保留被删除文件的扩展名。
- `recyclebin_evidence`（`evidence`）：逐卷扫描 `$Recycle.Bin` 及一级所有者目录，
  校验同目录 `$R` 的存在性与大小。

记录包含原始文件名/路径、原始大小、删除时间（UTC，`Timestamp`，时间线角色
`deleted`）、原始 FILETIME、`$I` 版本，以及 `$R` 状态、路径、是否存在、大小和
大小一致性。来源指向被解析的 `$I` 文件及其字节范围；损坏或不可读的 `$I`
产生告警（`INVALID_RECYCLE_METADATA`、`RESOURCE_LIMIT` 等），不会静默返回空结果。

边界：不恢复 `$R` 内容，不解析旧式 `INFO2`，不搜索深层目录，不修改检材。
证据范围每个卷最多 256 个所有者目录、20000 个目录项、4096 条 `$I` 候选；
单个 `$I` 最多 65564 字节。

## 构建与验证

```bash
cargo test --locked
cargo build --release --locked
lc-plugin-host --describe --library target/release/ljnljn_recyclebin.dll > schema.json
```

`schema.json` 由宿主 `--describe` 生成，应列出 `org.ljnljn.recyclebin`、
`recyclebin_files`、`recyclebin_evidence` 与 `windows.recyclebin.entry`。

## 安装布局

```text
ljnljn-recyclebin/
├── plugin.toml
├── ljnljn_recyclebin.dll
├── schema.json
└── locales/{en.toml,zh-CN.toml}
```

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
