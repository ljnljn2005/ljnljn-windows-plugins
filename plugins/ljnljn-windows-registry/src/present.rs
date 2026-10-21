//! 结果构造:AnalysisResult 的 artifact/finding/属性拼装。
//!
//! 约定:
//!   * 所有 artifact 都带 `source.path` / `source.paths` / `source.root` 与两份 hive 的
//!     SHA-256、字节长度(来源字段);
//!   * 哈希状态区分 present / unavailable(原因),绝不用猜测值填充;
//!   * 时间用 UTC ISO-8601 并注明原始时区未知。

use lovelycarve_plugin::{
    Artifact, Attributes, Finding, Severity, Value,
};

use crate::bootkey::BootKey;
use crate::sam_parse::{self, AccountRecord, HashState};
use crate::sources::LocatedHive;

/// artifact_type 命名空间
pub const NS: &str = "samhive";
/// 结果节点类型
pub const NODE_ACCOUNTS: &str = "account";
/// 单个 hive 的读取上限(与 sources::HIVE_READ_CAP 一致,写入来源属性便于复核)
pub const READ_CAP_NOTE: &str = "32 MiB";

/// 账号 artifact 的列定义(与属性键一一对应)
pub const ACCOUNT_COLUMNS: [(&str, &str); 19] = [
    ("samhive.accountName", "账号名"),
    ("samhive.accountSid", "账号 SID"),
    ("samhive.rid", "RID"),
    ("samhive.ntHashHex", "NT 哈希"),
    ("samhive.lmHashHex", "LM 哈希"),
    ("samhive.ntHashState", "NT 状态"),
    ("samhive.lmHashState", "LM 状态"),
    ("samhive.hashAlgorithm", "哈希算法"),
    ("samhive.loginCount", "登录次数"),
    ("samhive.lastLoginFiletime", "最后登录(FILETIME)"),
    ("samhive.lastLoginUtc", "最后登录(UTC)"),
    ("samhive.decryptOk", "解密校验"),
    ("samhive.decryptReason", "解密说明"),
    ("samhive.userKeyPath", "用户键路径"),
    ("samhive.ntOffset", "NT 偏移/长度"),
    ("samhive.lmOffset", "LM 偏移/长度"),
    ("samhive.limitations", "限制"),
    ("source.sam.path", "SAM 来源路径"),
    ("source.system.path", "SYSTEM 来源路径"),
];

fn source_attributes(
    attributes: &mut Attributes,
    sam: &LocatedHive,
    system: &LocatedHive,
    root_id: &str,
) {
    attributes.insert("source.root", root_id);
    attributes.insert("source.paths", format!("{}|{}", sam.path, system.path));
    attributes.insert("source.path", sam.path.clone());
    attributes.insert("source.sam.path", sam.path.clone());
    attributes.insert("source.sam.sha256", sam.sha256.clone());
    attributes.insert("source.sam.byteLen", sam.byte_len);
    attributes.insert("source.system.path", system.path.clone());
    attributes.insert("source.system.sha256", system.sha256.clone());
    attributes.insert("source.system.byteLen", system.byte_len);
    attributes.insert("source.readCap", READ_CAP_NOTE);
}

/// bootkey 来源 artifact
pub fn bootkey_artifact(
    bootkey: &BootKey,
    sam: &LocatedHive,
    system: &LocatedHive,
    root_id: &str,
) -> Artifact {
    let mut attributes = Attributes::new();
    source_attributes(&mut attributes, sam, system, root_id);
    attributes.insert("samhive.bootkeyHex", sam_parse::hex_lower(&bootkey.key));
    attributes.insert(
        "samhive.permutedHex",
        sam_parse::hex_lower(&bootkey.permuted),
    );
    attributes.insert("samhive.lsaPath", bootkey.base_path.join("\\"));
    attributes.insert(
        "samhive.lsaSubkeys",
        bootkey
            .class_sources
            .iter()
            .map(|source| source.subkey.as_str())
            .collect::<Vec<_>>()
            .join(","),
    );
    for source in &bootkey.class_sources {
        attributes.insert(
            format!("samhive.class.{}", source.subkey),
            source.class_name.clone(),
        );
        attributes.insert(
            format!("samhive.classCell.{}", source.subkey),
            source.cell,
        );
    }
    attributes.insert(
        "samhive.algorithm",
        "JD+Skew1+GBG+Data 的 8 组十六进制类名 → 32 字节 → 固定 permutation[8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7] → 16 字节 bootkey",
    );
    let mut value = Attributes::new();
    value.insert("bootkey", sam_parse::hex_lower(&bootkey.key));
    value.insert("permuted", sam_parse::hex_lower(&bootkey.permuted));
    Artifact {
        artifact_type: format!("{NS}.bootkey"),
        title: "bootkey(SysKey 派生)".to_string(),
        value: Some(value.to_value()),
        attributes,
    }
}

/// 账号 artifact(输出字段全集)
pub fn account_artifact(
    record: &AccountRecord,
    sam: &LocatedHive,
    system: &LocatedHive,
    root_id: &str,
) -> Artifact {
    let mut attributes = Attributes::new();
    source_attributes(&mut attributes, sam, system, root_id);
    attributes.insert("samhive.accountName", record.account_name.clone());
    attributes.insert_optional("samhive.accountSid", record.account_sid.clone());
    attributes.insert("samhive.rid", u64::from(record.rid));
    match &record.nt_hash {
        HashState::Present(hex) => {
            attributes.insert("samhive.ntHashHex", hex.clone());
            attributes.insert("samhive.ntHashState", "present");
        }
        HashState::Unavailable(reason) => {
            attributes.insert("samhive.ntHashHex", "unavailable");
            attributes.insert("samhive.ntHashState", reason.clone());
        }
    }
    match &record.lm_hash {
        HashState::Present(hex) => {
            attributes.insert("samhive.lmHashHex", hex.clone());
            attributes.insert("samhive.lmHashState", "present");
        }
        HashState::Unavailable(reason) => {
            attributes.insert("samhive.lmHashHex", "unavailable");
            attributes.insert("samhive.lmHashState", reason.clone());
        }
    }
    attributes.insert("samhive.hashAlgorithm", record.hash_algorithm);
    attributes.insert_optional("samhive.loginCount", record.login_count.map(u64::from));
    attributes.insert_optional("samhive.lastLoginFiletime", record.last_login_filetime);
    attributes.insert_optional("samhive.lastLoginUtc", record.last_login_utc.clone());
    attributes.insert(
        "samhive.lastLoginTimezone",
        "原始时区未知;FILETIME 按 UTC 展示为 ISO-8601",
    );
    attributes.insert("samhive.decryptOk", record.decrypt_ok);
    attributes.insert_optional("samhive.decryptReason", record.decrypt_reason.clone());
    attributes.insert("samhive.userKeyPath", record.user_key_path.clone());
    attributes.insert_optional("samhive.ntOffset", record.nt_offset.map(u64::from));
    attributes.insert_optional("samhive.ntLen", record.nt_len.map(u64::from));
    attributes.insert_optional("samhive.lmOffset", record.lm_offset.map(u64::from));
    attributes.insert_optional("samhive.lmLen", record.lm_len.map(u64::from));
    attributes.insert_optional("samhive.fRid", record.f_rid.map(u64::from));
    attributes.insert("samhive.limitations", record.limitations.join("; "));
    attributes.insert(
        "samhive.hiveSha256",
        format!("SAM={} SYSTEM={}", sam.sha256, system.sha256),
    );
    attributes.insert(
        "samhive.basis",
        "SAM\\SAM\\Domains\\Account\\Users\\<8 位十六进制 RID>:F(0x08 FILETIME,0x0C/0x10 用户名,0x30 RID,0x42 登录次数)、V(0x9C 哈希区结构头)→ RC4+AES-128-CBC+MD4 校验",
    );

    let mut value = Attributes::new();
    value.insert("accountName", record.account_name.clone());
    value.insert("rid", u64::from(record.rid));
    value.insert(
        "ntHashHex",
        match &record.nt_hash {
            HashState::Present(hex) => hex.clone(),
            HashState::Unavailable(reason) => format!("unavailable({reason})"),
        },
    );
    value.insert(
        "lmHashHex",
        match &record.lm_hash {
            HashState::Present(hex) => hex.clone(),
            HashState::Unavailable(reason) => format!("unavailable({reason})"),
        },
    );
    value.insert("hashAlgorithm", record.hash_algorithm);
    value.insert("decryptOk", record.decrypt_ok);
    Artifact {
        artifact_type: format!("{NS}.{NODE_ACCOUNTS}"),
        title: format!(
            "账号 {} (RID {}){}",
            record.account_name,
            record.rid,
            if record.decrypt_ok { "" } else { " [未解密]" }
        ),
        value: Some(value.to_value()),
        attributes,
    }
}

/// 解析失败/缺文件的 finding
pub fn error_finding(
    title: &str,
    description: String,
    sam: Option<&LocatedHive>,
    system: Option<&LocatedHive>,
    root_id: &str,
) -> Finding {
    let mut attributes = Attributes::new();
    attributes.insert("source.root", root_id);
    if let Some(sam) = sam {
        attributes.insert("source.sam.path", sam.path.clone());
        attributes.insert("source.sam.sha256", sam.sha256.clone());
    }
    if let Some(system) = system {
        attributes.insert("source.system.path", system.path.clone());
        attributes.insert("source.system.sha256", system.sha256.clone());
    }
    attributes.insert("samhive.basis", "REGF/hbin 结构校验与 Lsa/Users 定位");
    let _: Option<&Value> = None;
    Finding {
        severity: Severity::High,
        title: title.to_string(),
        description,
        attributes,
    }
}
