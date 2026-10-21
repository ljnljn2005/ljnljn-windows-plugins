//! SDK 句柄侧的 SAM + SYSTEM 定位与只读读取。
//!
//! 需求里的“输入是 SAM/SYSTEM 文件或包含二者的目录”在宿主里表达为:
//!   * `evidence_analyzer`:在检材各卷内按文件名(不区分大小写)查找 SAM 与 SYSTEM;
//!   * `file_analyzer`:单文件能力仅用于校验检材里的那一个文件是否是可解析的 REGF hive,
//!     并报告它属于 SAM / SYSTEM / 其他 —— 因为宿主不向插件暴露真实路径,
//!     单文件无法同时拿到两份 hive,完整提取请用 evidence_analyzer。
//!
//! 读取一律走 SDK 的 `EvidenceVolume` 只读句柄,带长度上限;插件从不使用 std::fs
//! 访问检材,也不修改任何文件。

use lovelycarve_plugin::{Error, EvidenceVolume, Result};

/// 单个 hive 的读取上限:真实 SAM/SYSTEM 一般为数 MB,32 MiB 足够覆盖异常大的 hive。
pub const HIVE_READ_CAP: u64 = 32 * 1024 * 1024;

/// 常见放置路径(优先探测,随后回退到全卷文件名扫描)
pub const WINDOWS_HIVES_DIR: &str =
    "Windows/System32/config";
pub const SAM_FALLBACK_DIRS: [&str; 3] = [
    "Windows/System32/config",
    "Windows.old/Windows/System32/config",
    "System32/config",
];

/// 检材内已定位的 hive 文件
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocatedHive {
    /// 检材内相对路径(SDK 路径,不带前导 `/`)
    pub path: String,
    /// 所在卷 root_id
    pub root_id: String,
    pub size: u64,
    /// 原始读入字节长度
    pub byte_len: u64,
    pub sha256: String,
}

impl LocatedHive {
    /// 来源标识:逻辑路径 + 卷 + 长度 + 摘要
    pub fn source_id(&self) -> String {
        format!("{}:{}", self.root_id, self.path)
    }
}

/// 目录内按文件名(不区分大小写)查找 SAM/SYSTEM 的候选排序规则:
/// 1. `Windows/System32/config/<name>`;2. 同目录层级更浅者;3. 字典序。
pub fn rank_candidates(name: &str, candidates: &[String]) -> Vec<String> {
    let mut ranked = candidates.to_vec();
    let lower_name = name.to_ascii_lowercase();
    let canonical_suffix = format!("{}/{lower_name}", WINDOWS_HIVES_DIR.to_ascii_lowercase());
    ranked.sort_by(|left, right| {
        let canonical =
            |path: &str| path.to_ascii_lowercase().ends_with(canonical_suffix.as_str());
        canonical(right)
            .cmp(&canonical(left))
            .then_with(|| left.matches('/').count().cmp(&right.matches('/').count()))
            .then_with(|| left.cmp(right))
    });
    ranked
}

/// 读取整份 hive(有上限、只读)。非文件返回 `None`。
pub fn read_hive(volume: &EvidenceVolume, path: &str) -> Result<Option<Vec<u8>>> {
    let Some(node) = volume.stat(path)? else {
        return Ok(None);
    };
    if !node.is_file() {
        return Ok(None);
    }
    if node.size == 0 {
        return Err(Error::new(
            "SHORT_READ",
            format!("{path} 长度为 0,不是可解析的注册表 hive"),
        ));
    }
    if node.size > HIVE_READ_CAP {
        return Err(Error::new(
            "RESOURCE_LIMIT",
            format!(
                "{path} 大小 {} 超过读取上限 {HIVE_READ_CAP} 字节",
                node.size
            ),
        ));
    }
    let bytes = volume.read(path, 0, Some(node.size))?;
    if bytes.len() as u64 != node.size {
        return Err(Error::new(
            "SHORT_READ",
            format!(
                "{path} 只读到 {} / {} 字节",
                bytes.len(),
                node.size
            ),
        ));
    }
    Ok(Some(bytes))
}

/// SHA-256(纯 Rust,不引入外部 crate)。
pub fn sha256_hex(bytes: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for index in 0..16 {
            words[index] = u32::from_be_bytes([
                block[index * 4],
                block[index * 4 + 1],
                block[index * 4 + 2],
                block[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut working = state;
        for index in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let ch = (working[4] & working[5]) ^ (!working[4] & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let maj = (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(maj);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }
        for index in 0..8 {
            state[index] = state[index].wrapping_add(working[index]);
        }
    }
    let mut out = String::with_capacity(64);
    for word in state {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

/// `path` 的最后一段文件名(检材内路径统一用 `/`)
pub fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// 文件名是否等于 `name`(不区分大小写)
pub fn name_matches(path: &str, name: &str) -> bool {
    file_name(path).eq_ignore_ascii_case(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_public_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn file_name_matching_is_case_insensitive() {
        assert!(name_matches("Windows/System32/config/sam", "SAM"));
        assert!(name_matches("Windows/System32/config/SYSTEM", "sYsTeM"));
        assert!(!name_matches("Windows/System32/config/SOFTWARE", "SAM"));
        assert_eq!(file_name("a/b/SAM"), "SAM");
    }

    #[test]
    fn canonical_config_path_ranks_first() {
        let candidates = vec![
            "Users/Public/sam".to_string(),
            "Windows/System32/config/SAM".to_string(),
            "Backup/Windows/System32/config/SAM".to_string(),
            "Windows/System32/config/RegBack/SAM".to_string(),
        ];
        let ranked = rank_candidates("SAM", &candidates);
        assert_eq!(ranked[0], "Windows/System32/config/SAM");
        // 层级更深/非标准位置的候选排在后面,但仍然保留(供 limitations 说明)
        assert_eq!(ranked.len(), candidates.len());
        assert!(ranked.contains(&"Users/Public/sam".to_string()));
    }
}
