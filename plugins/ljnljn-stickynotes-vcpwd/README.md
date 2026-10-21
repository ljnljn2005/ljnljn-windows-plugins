# ljnljn-stickynotes-vcpwd

LovelyCarve 原生插件（LPP v1 / C ABI v1），插件 ID `org.ljnljn.stickynotes-vcpwd`。

从便笺 CSV 中提取 VCpwd 凭据与上下文。

## 分析器

| 类型 | analyzer | 扩展名 |
| --- | --- | --- |
| 单文件 | `ljnljn.stickynotes-vcpwd` | csv, tsv, txt |

## 覆盖范围

- 编码识别：UTF-8(BOM/无BOM) / UTF-16LE+BOM / UTF-16BE+BOM / GBK / GB18030 回退
- 分隔符识别：逗号或制表符（按首逻辑记录字段数一致性判定）
- 标准 CSV 引号规则解析（双引号转义、跨行引号字段、CRLF/LF/CR 行尾）
- 逐行逐列键值抽取：键名 VCpwd（不区分大小写） + :/= /中文冒号
- 按值去重并统计出现次数，记录行号/列名或列序号/原始单元格文本（200 字符截断）
- unparsedRowCount 与 limitations 明确记录编码替换、字段数不齐、超限等降级情况

## 构建

仓库内置 LovelyCarve 插件 SDK（`vendor/lovelycarve-sdk`，AGPL-3.0），无需外部路径：

```bash
cargo test --locked
cargo build --release --locked
```

Windows 产物为 `target/release/ljnljn_kb_stickynotes_vcpwd_extract_dc952a12.dll`。

## 安装

把 `plugin.toml` 与构建出的 `ljnljn_kb_stickynotes_vcpwd_extract_dc952a12.dll` 放进 LovelyCarve 插件目录下的同名子目录，重启引擎后生效。插件使用 `isolation = "process"`。

## 取证边界

只读 CSV；不尝试解密或登录。

插件只读检材，不执行检材内容，不访问网络。已通过仓库内单元测试与 release 构建；尚未在真实 LovelyCarve GUI 与真实案件检材上完成端到端验证。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。内置 SDK 保留其原始许可证与协议文档。
