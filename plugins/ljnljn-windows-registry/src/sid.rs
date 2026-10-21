//! SID 结构解析与拼接。
//!
//! SID 二进制布局（微软官方文档）：
//! ```text
//! offset 0  revision          u8  (通常 1)
//! offset 1  sub_authority_count u8
//! offset 2  identifier_authority 6 字节**大端**整数
//! offset 8  sub_authority[n]  u32 **小端**，n = sub_authority_count
//! ```
//! 字符串形式为 `S-{revision}-{authority}` 后接每个子权威的十进制值，
//! 例如 `S-1-5-21-a-b-c-RID` 中权威是 5、子权威依次为 `21, a, b, c, RID`。

/// 计算机本地账号域的固定「三子权威」数量（`S-1-5-21-a-b-c`）。
pub const DOMAIN_SUB_AUTHORITIES: usize = 4;

/// 一个已解析的 SID。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sid {
    pub revision: u8,
    pub authority: u64,
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// 读取二进制 SID；长度不足或子权威数量不合理时返回 `None`。
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let revision = *bytes.first()?;
        let count = *bytes.get(1)? as usize;
        if count == 0 || count > 15 {
            return None;
        }
        let mut authority = 0_u64;
        for byte in bytes.get(2..8)? {
            authority = (authority << 8) | u64::from(*byte);
        }
        let mut sub_authorities = Vec::with_capacity(count);
        for index in 0..count {
            let at = 8 + index * 4;
            let raw = bytes.get(at..at + 4)?;
            sub_authorities.push(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]));
        }
        Some(Self {
            revision,
            authority,
            sub_authorities,
        })
    }

    /// 解析字符串形式；大小写不敏感，但必须严格符合 `S-1-5-…` 结构。
    pub fn parse_str(text: &str) -> Option<Self> {
        let mut parts = text.split('-');
        let head = parts.next()?;
        if !head.eq_ignore_ascii_case("S") {
            return None;
        }
        let revision: u8 = parts.next()?.parse().ok()?;
        let authority: u64 = parts.next()?.parse().ok()?;
        let mut sub_authorities = Vec::new();
        for part in parts {
            sub_authorities.push(part.parse().ok()?);
        }
        if sub_authorities.is_empty() {
            return None;
        }
        Some(Self {
            revision,
            authority,
            sub_authorities,
        })
    }

    /// 需要的二进制长度（含 4 字节单元头的考虑由调用方负责）。
    pub fn binary_len(&self) -> usize {
        8 + self.sub_authorities.len() * 4
    }

    /// 最后一个子权威（RID）；没有子权威时返回 `None`。
    pub fn last_sub_authority(&self) -> Option<u32> {
        self.sub_authorities.last().copied()
    }

    /// `S-1-5-21-a-b-c` 形式的域 SID 前缀；子权威不足 3 个时返回 `None`。
    pub fn domain_prefix(&self) -> Option<String> {
        if self.sub_authorities.len() < DOMAIN_SUB_AUTHORITIES {
            return None;
        }
        Some(self.to_string())
    }

    /// 用 `rid` 替换最后一个子权威；结构少于 1 个子权威时返回 `None`。
    pub fn with_rid(&self, rid: u32) -> Option<Self> {
        if self.sub_authorities.is_empty() {
            return None;
        }
        let mut next = self.clone();
        let last = next.sub_authorities.len() - 1;
        next.sub_authorities[last] = rid;
        Some(next)
    }
}

impl std::fmt::Display for Sid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "S-{}-{}", self.revision, self.authority)?;
        for sub in &self.sub_authorities {
            write!(formatter, "-{sub}")?;
        }
        Ok(())
    }
}

/// 判断字符串是否为 `S-1-5-<21 位及以上的子权威>` 形式的 SID 文本。
pub fn looks_like_sid(text: &str) -> bool {
    Sid::parse_str(text).is_some()
}

/// 解析 `S-1-5-21-a-b-c` 前缀（ProfileList 子键名去掉末位 RID 后的形态）。
pub fn domain_from_prefix(prefix: &str) -> Option<Sid> {
    let sid = Sid::parse_str(prefix)?;
    (sid.sub_authorities.len() >= DOMAIN_SUB_AUTHORITIES
        && sid.revision == 1
        && sid.authority == 5)
        .then_some(sid)
}

/// 生成 `S-1-5-21-a-b-c-RID` 形式的完整 SID 文本；参数非法时返回 `None`。
pub fn compose_sid(domain: &Sid, rid: u32) -> Option<String> {
    if domain.revision != 1 || domain.authority != 5 {
        return None;
    }
    if domain.sub_authorities.len() != DOMAIN_SUB_AUTHORITIES {
        return None;
    }
    let mut sub = domain.sub_authorities.clone();
    sub.push(rid);
    Some(Sid {
        revision: domain.revision,
        authority: domain.authority,
        sub_authorities: sub,
    }
    .to_string())
}

/// 按 SID 文本拆出 (域前缀, RID)：`S-1-5-21-a-b-c-r` → (`S-1-5-21-a-b-c`, r)。
pub fn split_sid(text: &str) -> Option<(String, u32)> {
    let sid = Sid::parse_str(text)?;
    let rid = sid.last_sub_authority()?;
    if sid.sub_authorities.len() != DOMAIN_SUB_AUTHORITIES + 1 {
        return None;
    }
    let prefix = Sid {
        revision: sid.revision,
        authority: sid.authority,
        sub_authorities: sid.sub_authorities[..DOMAIN_SUB_AUTHORITIES].to_vec(),
    };
    Some((prefix.to_string(), rid))
}

