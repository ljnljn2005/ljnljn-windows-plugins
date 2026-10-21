# ljnljn-chromium-history

LovelyCarve **LPP v2** 插件：解析 Chromium（Chrome / Edge）的 `History` SQLite
数据库，输出按配置与跨配置的 URL / 标题访问统计，以及 `downloads` 表的下载记录。

- 插件 ID：`org.ljnljn.chromium-history`
- 版本：`0.1.0`，协议 `2`
- SDK：`lovelycarve-plugin 0.2.0`，SQLite：`rusqlite 0.32.1`（`bundled`）
- 记录类型：`browser.profile`、`browser.url.profile`、`browser.url.total`、
  `browser.title.profile`、`browser.title.total`、`browser.download`

## 分析器

| ID | 作用域 | 输入 | 用途 |
| --- | --- | --- | --- |
| `history` | `system`（`windows`） | `Users/*/AppData/Local/Google/Chrome/User Data/*/History`、`Users/*/AppData/Local/Microsoft/Edge/User Data/*/History` | 当前系统全部 Chrome/Edge 配置 |
| `history_evidence` | `evidence` | 同上（每个卷） | 整体检材逐卷查找配置 |
| `history_file` | `files` | 用户选中的 `History` 数据库 | 已导出的单库 |

浏览器与配置名从输入路径推导：`Users/<user>/AppData/Local/<vendor>/.../User Data/<profile>/History`
→ `browser` = Chrome/Edge，`profile` = `<user>/<profile>`。文件作用域从文件名推导，
回退为 `Chromium` / 文件名。

## 记录

- **`browser.profile`**：每个配置一行，含解析状态、URL 行数、visits 行数、孤立
  visits（`visits.url` 没有对应 `urls.id`）、下载数、WAL/SHM 是否存在、主库头是否
  为 WAL 模式、`snapshot_scope=main_database_only`、快照说明与错误码/错误。
- **`browser.url.profile` / `browser.title.profile`**：每个配置内按 URL / 标题聚合：
  实际访问次数 `COUNT(visits.id)`、`urls.visit_count` 汇总（单独字段，绝不混同）、
  URL 行数、同一 URL 的标题集合 / 同一标题的 URL 集合、首次与末次访问 UTC。
- **`browser.url.total` / `browser.title.total`**：跨配置合并，带配置数、浏览器集合，
  并保留最多 16 个来源文件引用；更多来源由 `profiles` 计数体现。
- **`browser.download`**：`downloads` 表存在时逐行输出下载 ID、目标路径、来源页、
  referrer、站点、开始时间、已接收/总字节、状态码与状态、危险类型、中断原因、
  MIME 类型、当前路径。

时间：Chromium 的 1601 起微秒值只在有效时换算为 UTC；0 与越界值不伪造时间。

## SQL 语义

```sql
SELECT u.id, u.url, COALESCE(u.title,''), COALESCE(u.visit_count,0),
       COUNT(v.id), MIN(NULLIF(v.visit_time,0)), MAX(NULLIF(v.visit_time,0))
FROM urls AS u LEFT JOIN visits AS v ON v.url=u.id GROUP BY u.id
```

- 实际访问次数为 `COUNT(visits.id)`；`urls.visit_count` 单独保存为声明计数。
- 同一标题的不同 URL 合并；同一 URL 的不同标题保留在标题集合中。
- 孤立 visits 单独计数，不进入有 URL 的统计。
- `downloads` 列按固定白名单检测后动态选择；缺列以 NULL 填充，表不存在时不输出
  下载记录，不视为失败。

## 只读快照与 WAL

宿主只给逻辑文件句柄，SQLite 需要路径：插件把数据库字节复制到进程私有、带唯一
名称的临时文件，以 `mode=ro&immutable=1` 打开，关闭后删除。检材中的主库字节、
WAL/SHM 均不修改。

**不合并 WAL/SHM**：主库快照可能遗漏仍在 WAL 中的访问，标题取 `urls.title` 当前值。
每条配置记录都带 `snapshot_scope=main_database_only` 和说明；证据/系统作用域会检查
并报告 `-wal` / `-shm` 是否存在，但不读取它们。

## 限制

- 只扫描上述 Windows Chrome/Edge 标准 `User Data` 目录；便携版、自定义
  `--user-data-dir` 与其他平台需用文件分析器。
- 每库上限 64 MiB、100,000 URL 行、5,000,000 visits、100,000 下载；每配置
  URL+标题文本 1 MiB；单次 10,000 条记录；SQL 预算 30 秒并在每约 10,000 条
  VM 指令轮询取消。超限返回 `RESOURCE_LIMIT`，不截断后声称完整。
- 单库解析失败只影响该配置：记录为 `failed` 并产生告警；全部配置失败时有
  `CHROMIUM_ALL_PROFILES_FAILED` 告警。取消与资源超限会终止整个运行。
- 不恢复删除记录，不推断访问者身份。

## 构建与测试

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物：`target/release/ljnljn_chromium_history.dll`。

插件包目录：

```text
ljnljn-chromium-history/
├── plugin.toml
├── ljnljn_chromium_history.dll
├── schema.json
└── locales/{en,zh-CN}.toml
```

`schema.json` 由 `lc-plugin-host --describe --library <dll>` 生成。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
