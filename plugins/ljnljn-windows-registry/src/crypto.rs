//! 纯 Rust 密码学/摘要实现(无外部依赖,便于审计与离线复现)。
//!
//! * [`md4`]   Windows 口令哈希 = MD4(UTF-16LE 口令)
//! * [`md5`]   FakeBootKey = MD5(SysKey, 前 16 字节)
//! * [`rc4`]   Windows SAM 哈希区解密的 RC4-40 派生/加解密
//! * [`aes_cbc_decrypt`] / [`aes_cbc_encrypt_zero_iv`]  AES-128-CBC,IV 全零
//!
//! 仅用于解析已有的密文,不含任何口令破解/字典/在线攻击能力。

pub mod md4 {
    /// RFC 1320 MD4
    pub fn md4(input: &[u8]) -> [u8; 16] {
        let mut state: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
        let mut message = input.to_vec();
        let bit_len = (input.len() as u64).wrapping_mul(8);
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend_from_slice(&bit_len.to_le_bytes());
        for block in message.chunks_exact(64) {
            let mut x = [0u32; 16];
            for (index, slot) in x.iter_mut().enumerate() {
                *slot = u32::from_le_bytes([
                    block[index * 4],
                    block[index * 4 + 1],
                    block[index * 4 + 2],
                    block[index * 4 + 3],
                ]);
            }
            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
            let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
            let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
            macro_rules! step {
                ($a:ident, $b:ident, $c:ident, $d:ident, $f:ident, $k:expr, $s:expr) => {
                    $a = $a
                        .wrapping_add($f($b, $c, $d))
                        .wrapping_add(x[$k])
                        .rotate_left($s)
                };
            }
            // 轮 2/3 附加常量(仅用于第 1 轮以外的 K)
            macro_rules! step_k {
                ($a:ident, $b:ident, $c:ident, $d:ident, $f:ident, $k:expr, $s:expr, $cst:expr) => {
                    $a = $a
                        .wrapping_add($f($b, $c, $d))
                        .wrapping_add(x[$k])
                        .wrapping_add($cst)
                        .rotate_left($s)
                };
            }
            for k in [0usize, 4, 8, 12] {
                step!(a, b, c, d, f, k, 3);
                step!(d, a, b, c, f, k + 1, 7);
                step!(c, d, a, b, f, k + 2, 11);
                step!(b, c, d, a, f, k + 3, 19);
            }
            for k in [0usize, 1, 2, 3] {
                step_k!(a, b, c, d, g, k, 3, 0x5A82_7999);
                step_k!(d, a, b, c, g, k + 4, 5, 0x5A82_7999);
                step_k!(c, d, a, b, g, k + 8, 9, 0x5A82_7999);
                step_k!(b, c, d, a, g, k + 12, 13, 0x5A82_7999);
            }
            for k in [0usize, 2, 1, 3] {
                step_k!(a, b, c, d, h, k, 3, 0x6ED9_EBA1);
                step_k!(d, a, b, c, h, k + 8, 9, 0x6ED9_EBA1);
                step_k!(c, d, a, b, h, k + 4, 11, 0x6ED9_EBA1);
                step_k!(b, c, d, a, h, k + 12, 15, 0x6ED9_EBA1);
            }
            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
        }
        let mut out = [0u8; 16];
        for (index, word) in state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// MD5(RFC 1321),用于 Windows 的 FakeBootKey 派生。
    pub fn md5(input: &[u8]) -> [u8; 16] {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        let mut k = [0u32; 64];
        for (index, slot) in k.iter_mut().enumerate() {
            let angle = (index as f64 + 1.0).sin().abs();
            *slot = (angle * 4_294_967_296.0) as u32;
        }
        let mut state: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
        let mut message = input.to_vec();
        let bit_len = (input.len() as u64).wrapping_mul(8);
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend_from_slice(&bit_len.to_le_bytes());
        for block in message.chunks_exact(64) {
            let mut m = [0u32; 16];
            for (index, slot) in m.iter_mut().enumerate() {
                *slot = u32::from_le_bytes([
                    block[index * 4],
                    block[index * 4 + 1],
                    block[index * 4 + 2],
                    block[index * 4 + 3],
                ]);
            }
            let [mut a, mut b, mut c, mut d] = state;
            for index in 0..64 {
                let (f, g) = match index {
                    0..=15 => ((b & c) | (!b & d), index),
                    16..=31 => ((d & b) | (!d & c), (5 * index + 1) % 16),
                    32..=47 => (b ^ c ^ d, (3 * index + 5) % 16),
                    _ => (c ^ (b | !d), (7 * index) % 16),
                };
                let tmp = d;
                d = c;
                c = b;
                b = b.wrapping_add(
                    a.wrapping_add(f)
                        .wrapping_add(k[index])
                        .wrapping_add(m[g])
                        .rotate_left(S[index]),
                );
                a = tmp;
            }
            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
        }
        let mut out = [0u8; 16];
        for (index, word) in state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Windows 口令哈希:UTF-16LE 编码后 MD4。
    pub fn nt_hash_of_password(password: &str) -> [u8; 16] {
        let mut bytes = Vec::new();
        for unit in password.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        md4(&bytes)
    }
}

pub mod rc4 {
    /// RC4 流密码;`key` 为空时退化为恒等(不符合规范,调用方会单独报错)。
    pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        let mut s: [u8; 256] = [0; 256];
        for (index, slot) in s.iter_mut().enumerate() {
            *slot = index as u8;
        }
        let mut j = 0usize;
        for i in 0..256 {
            j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xFF;
            s.swap(i, j);
        }
        let mut out = Vec::with_capacity(data.len());
        let (mut i, mut j) = (0usize, 0usize);
        for byte in data {
            i = (i + 1) & 0xFF;
            j = (j + s[i] as usize) & 0xFF;
            s.swap(i, j);
            let index = (s[i] as usize + s[j] as usize) & 0xFF;
            out.push(byte ^ s[index]);
        }
        out
    }
}

pub mod aes {
    //! 最小 AES-128 实现(仅 CBC + 全零 IV),用于解密 SAM 哈希区。
    //! 对不可信数据只做纯内存解密,不涉及密钥搜索。

    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    fn inv_sbox() -> [u8; 256] {
        let mut inv = [0u8; 256];
        for (index, value) in SBOX.iter().enumerate() {
            inv[*value as usize] = index as u8;
        }
        inv
    }

    fn xtime(value: u8) -> u8 {
        (value << 1) ^ if value & 0x80 != 0 { 0x1B } else { 0 }
    }

    fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut result = 0u8;
        while b != 0 {
            if b & 1 != 0 {
                result ^= a;
            }
            a = xtime(a);
            b >>= 1;
        }
        result
    }

    /// AES 密钥扩展(仅 128 位),轮密钥按 16 字节一组。
    fn expand_key(key: &[u8]) -> Vec<[u8; 16]> {
        const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
        let mut words: Vec<[u8; 4]> = key.chunks_exact(4).map(|c| [c[0], c[1], c[2], c[3]]).collect();
        let nk = words.len();
        let total = 4 * (10 + 1);
        for index in nk..total {
            let mut temp = words[index - 1];
            if index % nk == 0 {
                temp = [
                    SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                    SBOX[temp[0] as usize],
                ];
                temp[0] ^= RCON[index / nk - 1];
            }
            let previous = words[index - nk];
            words.push([
                previous[0] ^ temp[0],
                previous[1] ^ temp[1],
                previous[2] ^ temp[2],
                previous[3] ^ temp[3],
            ]);
        }
        words
            .chunks(4)
            .map(|group| {
                let mut round = [0u8; 16];
                for (index, word) in group.iter().enumerate() {
                    round[index * 4..index * 4 + 4].copy_from_slice(word);
                }
                round
            })
            .collect()
    }

    fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
        for index in 0..16 {
            state[index] ^= key[index];
        }
    }

    fn inv_shift_rows(state: &mut [u8; 16]) {
        // state 为列主序:state[row + 4*col]
        let copy = *state;
        for row in 0..4 {
            for col in 0..4 {
                state[row + 4 * col] = copy[row + 4 * ((col + 4 - row) % 4)];
            }
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        let copy = *state;
        for row in 0..4 {
            for col in 0..4 {
                state[row + 4 * col] = copy[row + 4 * ((col + row) % 4)];
            }
        }
    }

    fn inv_sub_bytes(state: &mut [u8; 16], inv: &[u8; 256]) {
        for byte in state.iter_mut() {
            *byte = inv[*byte as usize];
        }
    }

    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }

    fn inv_mix_columns(state: &mut [u8; 16]) {
        for col in 0..4 {
            let base = col * 4;
            let (a0, a1, a2, a3) = (state[base], state[base + 1], state[base + 2], state[base + 3]);
            state[base] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
            state[base + 1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
            state[base + 2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
            state[base + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
        }
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for col in 0..4 {
            let base = col * 4;
            let (a0, a1, a2, a3) = (state[base], state[base + 1], state[base + 2], state[base + 3]);
            state[base] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
            state[base + 1] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
            state[base + 2] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
            state[base + 3] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
        }
    }

    fn decrypt_block(key: &[[u8; 16]], block: &[u8]) -> [u8; 16] {
        let inv = inv_sbox();
        let mut state = [0u8; 16];
        state.copy_from_slice(&block[..16]);
        add_round_key(&mut state, &key[10]);
        for round in (1..10).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state, &inv);
            add_round_key(&mut state, &key[round]);
            inv_mix_columns(&mut state);
        }
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state, &inv);
        add_round_key(&mut state, &key[0]);
        state
    }

    fn encrypt_block(key: &[[u8; 16]], block: &[u8]) -> [u8; 16] {
        let mut state = [0u8; 16];
        state.copy_from_slice(&block[..16]);
        add_round_key(&mut state, &key[0]);
        for round in 1..10 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &key[round]);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &key[10]);
        state
    }

    /// AES-128-CBC 解密(IV 全零);输入长度必须是 16 的倍数。
    pub fn decrypt_zero_iv(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        if key.len() != 16 {
            return None;
        }
        if data.is_empty() || data.len() % 16 != 0 {
            return None;
        }
        let schedule = expand_key(key);
        let mut out = Vec::with_capacity(data.len());
        let mut previous = [0u8; 16];
        for block in data.chunks_exact(16) {
            let plain = decrypt_block(&schedule, block);
            for index in 0..16 {
                out.push(plain[index] ^ previous[index]);
            }
            previous.copy_from_slice(block);
        }
        Some(out)
    }

    /// AES-128-CBC 加密(IV 全零);输入长度必须是 16 的倍数。
    pub fn encrypt_zero_iv(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        if key.len() != 16 || data.is_empty() || data.len() % 16 != 0 {
            return None;
        }
        let schedule = expand_key(key);
        let mut out = Vec::with_capacity(data.len());
        let mut previous = [0u8; 16];
        for block in data.chunks_exact(16) {
            let mut mixed = [0u8; 16];
            for index in 0..16 {
                mixed[index] = block[index] ^ previous[index];
            }
            previous = encrypt_block(&schedule, &mixed);
            out.extend_from_slice(&previous);
        }
        Some(out)
    }
}

/// AES-128-CBC 解密入口(IV 全零);密钥长度或密文非法时返回 `None`。
pub fn aes_cbc_decrypt_zero_iv(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    aes::decrypt_zero_iv(key, data)
}

/// AES-128-CBC 加密入口(IV 全零),仅用于合成测试数据构造。
pub fn aes_cbc_encrypt_zero_iv(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    aes::encrypt_zero_iv(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 已知答案来自公开测试向量(RFC 1320/1321、FIPS-197),不是案件取值。
    #[test]
    fn md4_matches_rfc1320_vectors() {
        assert_eq!(hex(&md4::md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex(&md4::md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(
            hex(&md4::md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        );
    }

    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(hex(&md4::md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md4::md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn nt_hash_of_password_is_md4_of_utf16le() {
        let bytes: Vec<u8> = "Password123!"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(md4::nt_hash_of_password("Password123!"), md4::md4(&bytes));
        // 非 ASCII 口令同样按 UTF-16LE
        let hash = md4::nt_hash_of_password("密码");
        assert_ne!(hash, [0u8; 16]);
    }

    #[test]
    fn aes128_fips197_vector_round_trip() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plain: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let cipher = aes::encrypt_zero_iv(&key, &plain).expect("encrypt");
        assert_eq!(hex(&cipher[..16]), "69c4e0d86a7b0430d8cdb78070b4c55a");
        let back = aes::decrypt_zero_iv(&key, &cipher).expect("decrypt");
        assert_eq!(back, plain.to_vec());
    }

    #[test]
    fn rc4_matches_public_vector() {
        // 公开向量:key="Key", plaintext="Plaintext" → BBF316E8D940AF0AD3
        let out = rc4::rc4(b"Key", b"Plaintext");
        assert_eq!(hex(&out), "bbf316e8d940af0ad3");
    }

    #[test]
    fn invalid_key_lengths_are_rejected() {
        assert!(aes_cbc_decrypt_zero_iv(&[0u8; 15], &[0u8; 16]).is_none());
        assert!(aes_cbc_decrypt_zero_iv(&[0u8; 16], &[0u8; 15]).is_none());
        assert!(aes_cbc_decrypt_zero_iv(&[0u8; 16], &[]).is_none());
    }
}
