# ljnljn-psreadline（LPP v2）

从 LPP v1 迁移的 PowerShell PSReadLine 历史 URL 插件，解析器保持原实现
（逻辑命令合并、字面 `http(s)://` 提取、UTF-8 / BOM UTF-16）。

- 插件 ID：`org.ljnljn.psreadline`
- `psreadline_files`（`files`，扩展名 `txt`）：用户选中的历史文件。
- `psreadline_evidence`（`evidence`）：逐卷扫描标准用户目录下的
  `AppData/Roaming/Microsoft[/Windows]/PowerShell/PSReadLine/ConsoleHost_history.txt`。
- 记录类型：`psreadline.history`（每文件命令数/含 URL 命令数）、
  `psreadline.command`（行号、逻辑命令、URL 列表）、`psreadline.total`
  （检材模式的总计数）。

历史文件没有可靠的执行时间，因此不生成时间线字段；URL 只是字面命中，不证明
命令执行或请求成功。超出 4 MiB、编码损坏或未完成续行会按文件产生告警
（`RESOURCE_LIMIT`、`INVALID_HISTORY`），不会静默返回空成功。自动扫描不覆盖
自定义 `HistorySavePath`、其他 host 的历史和已删除历史。

## 构建与验证

```bash
cargo test --locked
cargo build --release --locked
lc-plugin-host --describe --library target/release/ljnljn_psreadline.dll > schema.json
```

`schema.json` 应列出 `org.ljnljn.psreadline`、`psreadline_files`、
`psreadline_evidence` 以及三种 `psreadline.*` 记录。

## 安装布局

```text
ljnljn-psreadline/
├── plugin.toml
├── ljnljn_psreadline.dll
├── schema.json
└── locales/{en.toml,zh-CN.toml}
```

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
