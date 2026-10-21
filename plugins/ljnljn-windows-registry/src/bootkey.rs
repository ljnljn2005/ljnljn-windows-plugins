//! bootkey(SysKey)派生:SYSTEM\CurrentControlSet\Control\Lsa 下 JD/Skew1/GBG/Data
//! 四个子键的类名 → 置换前数据 → 固定 permutation 重排 → 16 字节 bootkey。
//!
//! 尺寸关系(与公开实现一致):每个子键的类名是 8 个十六进制字符(4 字节),
//! 四个类名共 32 个十六进制字符 = 16 字节置换前数据;`PERMUTATION` 是 16 元素表,
//! `bootkey[i] = permuted[PERMUTATION[i]]`。需求文字里的“32 字节”指 32 个十六进制字符;
//! 若某子键类名不是 8 个十六进制字符,直接以 `signature` 阶段失败,不做猜测。
//!
//! 可选地用 SAM 的 `Domains\Account\F` 派生 FakeBootKey(哈希区 AES 密钥链的一环),
//! 失败只记入 limitations,不阻断主流程。

use crate::crypto::md4::md5;
use crate::regf::{Hive, RegfError, RegfResult, RegfStage};
use crate::sam_parse::PERMUTATION;

/// Lsa 子键(按拼接顺序)
pub const LSA_SUBKEYS: [&str; 4] = ["JD", "Skew1", "GBG", "Data"];
/// 相对 SYSTEM 根键的 Lsa 键路径
pub const LSA_PATH: [&str; 3] = ["CurrentControlSet", "Control", "Lsa"];
/// 离线 hive 中 CurrentControlSet 不可解析时的回退路径
pub const LSA_FALLBACK_PATH: [&str; 3] = ["ControlSet001", "Control", "Lsa"];
/// 每个类名的十六进制字符数(4 字节)
pub const CLASS_HEX_LEN: usize = 8;

#[derive(Clone, Debug, PartialEq)]
pub struct BootKey {
    /// 16 字节置换前数据(JD+Skew1+GBG+Data 依次拼接,每个 4 字节)
    pub permuted: Vec<u8>,
    /// 16 字节 bootkey
    pub key: [u8; 16],
    /// 每个子键的来源:单元偏移 + 类名原文
    pub class_sources: Vec<ClassSource>,
    /// 实际使用的键路径
    pub base_path: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClassSource {
    pub subkey: String,
    /// 子键单元绝对偏移(定位线索)
    pub cell: u64,
    pub class_name: String,
}

/// 置换前数据经固定 permutation 重排为 16 字节 bootkey。
///
/// `bootkey[i] = permuted[PERMUTATION[i]]`;要求长度恰为 16。
pub fn permute(permuted: &[u8]) -> Option<[u8; 16]> {
    if permuted.len() != 16 {
        return None;
    }
    let mut key = [0u8; 16];
    for (index, target) in PERMUTATION.iter().enumerate() {
        key[index] = permuted[*target];
    }
    Some(key)
}

/// 四个类名(每个 8 个十六进制字符)→ 16 字节置换前数据。
pub fn classes_to_permuted(classes: &[String; 4]) -> RegfResult<Vec<u8>> {
    let mut permuted = Vec::with_capacity(16);
    for (index, class) in classes.iter().enumerate() {
        let subkey = LSA_SUBKEYS[index];
        if class.len() != CLASS_HEX_LEN {
            return Err(RegfError::new(
                RegfStage::Signature,
                format!(
                    "Lsa 子键 {subkey} 类名期望 {CLASS_HEX_LEN} 个十六进制字符,实际 \"{class}\"({} 字符)",
                    class.len()
                ),
            ));
        }
        for pair in 0..4 {
            let hex = &class[pair * 2..pair * 2 + 2];
            let byte = u8::from_str_radix(hex, 16).map_err(|_| {
                RegfError::new(
                    RegfStage::Signature,
                    format!("Lsa 子键 {subkey} 类名字符 \"{hex}\" 不是十六进制"),
                )
            })?;
            permuted.push(byte);
        }
    }
    Ok(permuted)
}

/// 从已打开的 SYSTEM hive 派生 bootkey。
///
/// 依次尝试 `CurrentControlSet\Control\Lsa` 与 `ControlSet001\Control\Lsa`
/// (离线 hive 中 CurrentControlSet 对 CURRENT 符号链的解析由提取方完成,
/// 这里做明确的路径回退并把实际路径写回结果)。
pub fn derive_bootkey(hive: &Hive) -> RegfResult<BootKey> {
    let mut attempts = Vec::new();
    let mut first_error: Option<RegfError> = None;
    for path in [LSA_PATH, LSA_FALLBACK_PATH] {
        match derive_with_path(hive, &path) {
            Ok(bootkey) => return Ok(bootkey),
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error.clone());
                }
                attempts.push(format!("{}: {error}", path.join("\\")));
            }
        }
    }
    let mut error =
        first_error.unwrap_or_else(|| RegfError::new(RegfStage::Missing, "未找到任何 Lsa 键"));
    error.message = format!("{}; 已尝试 {}", error.message, attempts.join(" | "));
    Err(error)
}

fn derive_with_path(hive: &Hive, base: &[&str]) -> RegfResult<BootKey> {
    let mut path: Vec<&str> = base.to_vec();
    // 先确认 Lsa 键可定位,再逐个子键取类名
    hive.open_key(&path)?;
    let mut classes: [String; 4] = Default::default();
    let mut sources = Vec::new();
    for (index, subkey) in LSA_SUBKEYS.iter().enumerate() {
        path.push(subkey);
        let sub_cell = hive.open_key(&path).map_err(|error| {
            RegfError::new(
                error.stage,
                format!("{}\\{}: {}", base.join("\\"), subkey, error.message),
            )
        })?;
        path.pop();
        let class = hive.key_class(sub_cell)?;
        sources.push(ClassSource {
            subkey: (*subkey).to_string(),
            cell: sub_cell,
            class_name: class.clone(),
        });
        classes[index] = class;
    }
    let permuted = classes_to_permuted(&classes)?;
    let key = permute(&permuted)
        .ok_or_else(|| RegfError::new(RegfStage::Signature, "置换前数据不是 16 字节"))?;
    let mut path_out: Vec<String> = base.iter().map(|part| (*part).to_string()).collect();
    path_out.push("Lsa".to_string());
    Ok(BootKey {
        permuted,
        key,
        class_sources: sources,
        base_path: path_out,
    })
}

/// FakeBootKey:SAM `Domains\Account\F` 值前 16 字节的 MD5。
/// 用于哈希区 AES 密钥链;可选,失败只记 limitations。
pub fn faux_secret(hive: &Hive) -> RegfResult<[u8; 16]> {
    // F 是 Account 键下的一个值，不是子键；兼容 根 SAM -> Domains 与
    // 根 SAM -> 子 SAM -> Domains 两种布局。
    let account = hive
        .open_key(&["SAM", "Domains", "Account"])
        .or_else(|_| hive.open_key(&["Domains", "Account"]))
        .map_err(|error| {
            RegfError::new(
                error.stage,
                format!("SAM/SAM\\Domains\\Account: {}", error.message),
            )
        })?;
    let values = hive.values(account)?;
    let Some(value) = values.iter().find(|value| value.name == "F") else {
        return Err(RegfError::new(
            RegfStage::Missing,
            "SAM\\Domains\\Account 不含 F 值",
        ));
    };
    let data = hive.value_data(value)?;
    if data.len() < 0x18 {
        return Err(RegfError::new(
            RegfStage::Cell,
            format!("SAM\\Domains\\Account\\F 长度 {} 小于 0x18", data.len()),
        ));
    }
    // FakeBootKey 是 F 值偏移 0x08 处的 16 字节（0x00..0x08 为头部）。
    Ok(md5(&data[0x08..0x18]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permute_uses_fixed_order() {
        let mut permuted = [0u8; 16];
        for (index, slot) in permuted.iter_mut().enumerate() {
            *slot = index as u8;
        }
        let key = permute(&permuted).expect("16 bytes");
        for (index, target) in PERMUTATION.iter().enumerate() {
            assert_eq!(key[index], *target as u8);
        }
    }

    #[test]
    fn permute_rejects_wrong_length() {
        assert!(permute(&[0u8; 15]).is_none());
        assert!(permute(&[0u8; 17]).is_none());
        assert!(permute(&[0u8; 32]).is_none());
    }

    #[test]
    fn classes_require_eight_hex_chars() {
        let good = [
            "01020304".to_string(),
            "05060708".to_string(),
            "090A0B0C".to_string(),
            "0D0E0F10".to_string(),
        ];
        let permuted = classes_to_permuted(&good).expect("valid classes");
        // 32 个十六进制字符 = 16 字节
        assert_eq!(permuted.len(), 16);
        assert_eq!(&permuted[0..4], &[0x01, 0x02, 0x03, 0x04]);

        let short = [
            "0102030".to_string(),
            "05060708".to_string(),
            "090A0B0C".to_string(),
            "0D0E0F10".to_string(),
        ];
        let error = classes_to_permuted(&short).expect_err("short class");
        assert_eq!(error.stage, RegfStage::Signature);

        let messy = [
            "0102030Z".to_string(),
            "05060708".to_string(),
            "090A0B0C".to_string(),
            "0D0E0F10".to_string(),
        ];
        assert!(classes_to_permuted(&messy).is_err());
    }
}
