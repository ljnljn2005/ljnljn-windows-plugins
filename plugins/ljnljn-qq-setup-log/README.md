# ljnljn-qq-setup-log

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.qq-setup-log`。

从 qq_setup.log 提取安装、完成与启动标记的时间片段。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 单文件 | `ljnljn.qq-setup-log` | log, txt |

## 覆盖范围

- qq_setup.log 编码判定：UTF-8（含 BOM）→ GBK → 替换字符降级
- mmdd/hhmmss（4 位月日 + 斜杠 + 6 位时分秒）时间片段逐行抽取，保留原文
- 同行大小写不敏感分类：setup/install/开始安装/正在安装=install，完成/complete/success=complete，Show QQ Window/启动/launch=launch，其余含时间行为 other
- 事件按日志行序输出，保留行号与行原文（截断 200 字符）
- 无时间戳行计数 unparsedLineCount；越界时间值原值保留并列入 limitations

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_qq_setup_timeline_d569c0d3.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_qq_setup_timeline_d569c0d3.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

只解析文本日志，不执行日志中的命令。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
