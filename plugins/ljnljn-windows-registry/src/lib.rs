//! SAM + SYSTEM 注册表 hive 离线解析:SysKey/bootkey 派生与账号 NT/LM 哈希提取。
//!
//! 需求映射:
//!   * 输入 = 同一目录下的 SAM 与 SYSTEM 两份 hive(文件名不区分大小写);
//!     在 SDK 里表现为“同一卷上的 SAM 与 SYSTEM”,由 [`analyzer`] 只读读取。
//!   * 算法一见 [`bootkey`]:校验 REGF/hbin,读取 Lsa 下 JD/Skew1/GBG/Data 的类名,
//!     拼接 32 字节后按固定置换表得到 16 字节 bootkey,失败给出具体阶段。
//!   * 算法二见 [`sam_parse`]:Users 下 8 位十六进制子键的 F/V 值 → 账号、RID、
//!     登录次数、最后登录 FILETIME、NT/LM 加密区 → RC4 + AES-CBC 解密 + AAD 校验。
//!   * 不包含任何口令破解、字典、彩虹表、在线攻击,也不解析 NTDS.dit/域缓存/DPAPI。
//!
//! 输出每条 artifact 都带来源属性(`source.path` / `source.paths` / `source.root`)
//! 与检材 hive 的 SHA-256,便于复核。

mod analyzer;
mod bootkey;
mod crypto;
mod logger;
mod present;
mod regf;
mod sam_parse;
mod registry_artifacts;
mod sid;
mod sources;
#[cfg(test)]
mod testhive;

pub use analyzer::SamHiveAnalyzer;
pub use registry_artifacts::{ANALYZER_POLICY, ANALYZER_UNINSTALL, ANALYZER_USBSTOR, ANALYZER_VERSION};

/// 插件标识(必须与 plugin.toml 的 `id` 完全一致)
pub const PLUGIN_ID: &str = "org.ljnljn.windows-registry";
/// 显示名
pub const PLUGIN_NAME: &str = "Windows注册表取证";
/// 版本(必须与 plugin.toml 的 `version` 一致)
pub const PLUGIN_VERSION: &str = "0.1.0";
/// analyzer 名(必须与 plugin.toml 的 `[[capabilities]].analyzer` 一致)
pub const ANALYZER_NAME: &str = "ljnljn.windows-registry";

fn plugin() -> lovelycarve_plugin::Plugin {
    lovelycarve_plugin::Plugin::new(PLUGIN_ID, PLUGIN_NAME, PLUGIN_VERSION)
        .evidence_analyzer(SamHiveAnalyzer)
        .file_analyzer(registry_artifacts::SoftwareVersionAnalyzer)
        .file_analyzer(registry_artifacts::UninstallAnalyzer)
        .file_analyzer(registry_artifacts::UsbStorAnalyzer)
        .file_analyzer(registry_artifacts::SamPolicyAnalyzer)
}

lovelycarve_plugin::export_plugin!(plugin);

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn plugin_toml_identity_matches_code() {
        let toml = include_str!("../plugin.toml");
        assert!(toml.contains(&format!("id = \"{PLUGIN_ID}\"")));
        assert!(toml.contains(&format!("version = \"{PLUGIN_VERSION}\"")));
        assert!(toml.contains(&format!("analyzer = \"{ANALYZER_NAME}\"")));
        assert!(toml.contains(&format!("analyzer = \"{ANALYZER_VERSION}\"")));
        assert!(toml.contains(&format!("analyzer = \"{ANALYZER_UNINSTALL}\"")));
        assert!(toml.contains(&format!("analyzer = \"{ANALYZER_USBSTOR}\"")));
        assert!(toml.contains(&format!("analyzer = \"{ANALYZER_POLICY}\"")));
        assert!(toml.contains("type = \"evidence_analyzer\""));
        assert!(toml.contains("permissions = [\"emit_artifacts\"]"));
        assert!(toml.contains("path = \"ljnljn_kb_sam_hive_hash_extract_da5e5db1\""));
        assert!(toml.contains("isolation = \"process\""));
    }
}
