//! SDK 侧分析器:`evidence_analyzer` 定位并解析检材里的 SAM 与 SYSTEM hive。
//!
//! 设计要点:
//!   * 只读:全部读取经 `EvidenceVolume` 句柄(带长度上限),不使用 std::fs。
//!   * 优雅跳过:卷内找不到 SAM/SYSTEM 时继续下一卷;所有卷都没有两者时明确报错,
//!     不返回“空成功”。
//!   * 损坏与解析失败如实记录:REGF/解析错误写入 limitations 与 findings,
//!     并给出具体失败阶段。
//!   * 每条 artifact 带 `source.path` / `source.paths` / `source.root` 与 hive SHA-256。

use lovelycarve_plugin::{
    AnalysisResult, Evidence, EvidenceAnalyzer, EvidenceVolume, LogLevel, Result, ResultColumn,
    ResultNode, Value,
};

use crate::present::{
    account_artifact, bootkey_artifact, error_finding, ACCOUNT_COLUMNS, NODE_ACCOUNTS,
};
use crate::regf::{Hive, RegfError};
use crate::sam_parse::{self, HashState};
use crate::sources::{self, LocatedHive};
use crate::ANALYZER_NAME;

/// 每卷最多处理的账号数(SDK 结果上限 10,000 项)
const MAX_ACCOUNTS: usize = 5_000;

/// `evidence_analyzer` 实现
pub struct SamHiveAnalyzer;

impl EvidenceAnalyzer for SamHiveAnalyzer {
    fn analyzer(&self) -> &str {
        ANALYZER_NAME
    }

    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        let mut result = AnalysisResult::default();
        let mut limitations: Vec<String> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        let roots = evidence.roots()?;
        if roots.is_empty() {
            return Err(lovelycarve_plugin::Error::new(
                "NO_ROOTS",
                "检材没有可浏览的卷,无法定位 SAM/SYSTEM hive",
            ));
        }
        let mut found_any = false;
        let mut parsed_any = false;
        for (index, root) in roots.iter().enumerate() {
            evidence.context().check_cancelled()?;
            let volume = evidence.volume(&root.root_id);
            evidence.progress(
                index as u64 + 1,
                Some(roots.len() as u64),
                Some(&format!("查找 {} 上的 SAM/SYSTEM hive", root.root_id)),
            )?;

            let (sam_hit, system_hit) = match locate_hives(&volume, evidence) {
                Ok(located) => located,
                Err(error) => {
                    if error.is_cancelled() {
                        return Err(error);
                    }
                    evidence.context().log(
                        LogLevel::Warn,
                        &format!("卷 {} 查找 hive 失败: {error}", root.root_id),
                    );
                    limitations.push(format!("卷 {}:无法枚举文件名({error})", root.root_id));
                    continue;
                }
            };
            if sam_hit.is_none() && system_hit.is_none() {
                continue;
            }
            found_any = true;
            let missing = match (&sam_hit, &system_hit) {
                (None, None) => unreachable!(),
                (None, Some(_)) => Some("SAM"),
                (Some(_), None) => Some("SYSTEM"),
                (Some(_), Some(_)) => None,
            };
            if let Some(missing) = missing {
                let present = if missing == "SAM" { "SYSTEM" } else { "SAM" };
                let reason = format!(
                    "卷 {}:找到 {present} 但缺少 {missing} hive,无法完成 bootkey 派生/账号提取;已按需求明确报错而非返回空结果",
                    root.root_id
                );
                evidence.context().log(LogLevel::Error, &reason);
                limitations.push(reason.clone());
                result.findings.push(error_finding(
                    &format!("缺少 {missing} hive"),
                    reason,
                    sam_hit.as_ref(),
                    system_hit.as_ref(),
                    &root.root_id,
                ));
                continue;
            }
            let (Some(sam_hit), Some(system_hit)) = (sam_hit, system_hit) else {
                continue;
            };

            evidence.progress(0, Some(3), Some("读取 SAM/SYSTEM 并校验 REGF"))?;
            let sam_bytes = read_located(&volume, &sam_hit)?;
            let system_bytes = read_located(&volume, &system_hit)?;
            let sam = LocatedHive {
                byte_len: sam_bytes.len() as u64,
                sha256: sources::sha256_hex(&sam_bytes),
                ..sam_hit
            };
            let system = LocatedHive {
                byte_len: system_bytes.len() as u64,
                sha256: sources::sha256_hex(&system_bytes),
                ..system_hit
            };

            let sam_hive = match Hive::open(sam_bytes) {
                Ok(hive) => hive,
                Err(error) => {
                    let detail = describe_regf_error("SAM", &sam, &error);
                    evidence.context().log(LogLevel::Error, &detail);
                    limitations.push(detail.clone());
                    result.findings.push(error_finding(
                        "SAM hive 无法解析",
                        detail,
                        Some(&sam),
                        Some(&system),
                        &root.root_id,
                    ));
                    continue;
                }
            };
            let system_hive = match Hive::open(system_bytes) {
                Ok(hive) => hive,
                Err(error) => {
                    let detail = describe_regf_error("SYSTEM", &system, &error);
                    evidence.context().log(LogLevel::Error, &detail);
                    limitations.push(detail.clone());
                    result.findings.push(error_finding(
                        "SYSTEM hive 无法解析",
                        detail,
                        Some(&sam),
                        Some(&system),
                        &root.root_id,
                    ));
                    continue;
                }
            };

            evidence.progress(1, Some(3), Some("派生 bootkey(JD/Skew1/GBG/Data)"))?;
            let extraction = match sam_parse::extract(&system_hive, &sam_hive) {
                Ok(extraction) => extraction,
                Err(reason) => {
                    evidence.context().log(LogLevel::Error, &reason);
                    limitations.push(reason.clone());
                    result.findings.push(error_finding(
                        "提取失败",
                        reason,
                        Some(&sam),
                        Some(&system),
                        &root.root_id,
                    ));
                    continue;
                }
            };
            parsed_any = true;
            evidence.progress(2, Some(3), Some("输出账号与哈希"))?;

            let bootkey = &extraction.bootkey;
            notes.push(format!(
                "卷 {}:bootkey 由 {}\\{{{}}} 类名派生",
                root.root_id,
                bootkey.base_path.join("\\"),
                bootkey
                    .class_sources
                    .iter()
                    .map(|source| source.subkey.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            limitations.extend(
                extraction
                    .limitations
                    .iter()
                    .map(|note| format!("卷 {}: {note}", root.root_id)),
            );
            result
                .artifacts
                .push(bootkey_artifact(bootkey, &sam, &system, &root.root_id));

            for record in extraction.accounts.iter().take(MAX_ACCOUNTS) {
                limitations.extend(record.limitations.iter().map(|note| {
                    format!("卷 {} 账号 {}: {note}", root.root_id, record.user_key_name)
                }));
                if let HashState::Unavailable(reason) = &record.nt_hash {
                    notes.push(format!(
                        "卷 {} 账号 {} NT 哈希 unavailable:{}",
                        root.root_id, record.account_name, reason
                    ));
                }
                result
                    .artifacts
                    .push(account_artifact(record, &sam, &system, &root.root_id));
            }
            if extraction.accounts.len() > MAX_ACCOUNTS {
                limitations.push(format!(
                    "卷 {}:账号数 {} 超过单次输出上限 {MAX_ACCOUNTS},其余未输出",
                    root.root_id,
                    extraction.accounts.len()
                ));
            }
            result.nodes.push(ResultNode {
                node_type: NODE_ACCOUNTS.to_string(),
                name: format!("账号哈希(卷 {})", root.root_id),
                columns: ACCOUNT_COLUMNS
                    .iter()
                    .map(|(key, label)| ResultColumn {
                        key: (*key).to_string(),
                        label: (*label).to_string(),
                    })
                    .collect(),
            });
        }

        if !found_any {
            return Err(lovelycarve_plugin::Error::new(
                "EVIDENCE_PATH_NOT_FOUND",
                "检材内未找到名为 SAM/SYSTEM 的注册表 hive;请确认检材包含 Windows\\System32\\config,或先提取该目录后作为文件检材导入",
            ));
        }
        if !parsed_any {
            let detail = if limitations.is_empty() {
                "原因未知".to_string()
            } else {
                limitations.join("; ")
            };
            result.summary = Some(format!("已找到 SAM/SYSTEM 但未提取到账号:{detail}"));
            result.findings.push(error_finding(
                "未提取到账号哈希",
                detail,
                None,
                None,
                "all",
            ));
            return Ok(result);
        }

        let account_count = result
            .artifacts
            .iter()
            .filter(|artifact| artifact.artifact_type == format!("samhive.{NODE_ACCOUNTS}"))
            .count();
        let resolved = result
            .artifacts
            .iter()
            .filter(|artifact| artifact.artifact_type == format!("samhive.{NODE_ACCOUNTS}"))
            .filter(|artifact| {
                matches!(
                    artifact.attributes.get("samhive.decryptOk"),
                    Some(Value::Boolean(true))
                )
            })
            .count();
        let mut summary = format!(
            "SAM/SYSTEM hive 解析完成:账号 {account_count} 个,解密校验通过 {resolved} 个;来源与哈希见各 artifact 的 source.* / samhive.* 属性"
        );
        if !limitations.is_empty() {
            summary.push_str(&format!(
                ";限制 {} 条:{}",
                limitations.len(),
                limitations.join("; ")
            ));
        }
        result.summary = Some(summary);
        for note in notes {
            evidence.context().log(LogLevel::Info, &note);
        }
        Ok(result)
    }
}

fn locate_hives(
    volume: &EvidenceVolume,
    evidence: &Evidence,
) -> Result<(Option<LocatedHive>, Option<LocatedHive>)> {
    let scanned = volume.find_files_by_name(&["SAM", "SYSTEM"], &[], &[])?;
    let sam_candidates: Vec<String> = scanned
        .iter()
        .filter(|path| sources::name_matches(path, "SAM"))
        .cloned()
        .collect();
    let system_candidates: Vec<String> = scanned
        .iter()
        .filter(|path| sources::name_matches(path, "SYSTEM"))
        .cloned()
        .collect();
    if !sam_candidates.is_empty() || !system_candidates.is_empty() {
        evidence.context().log(
            LogLevel::Debug,
            &format!(
                "卷 {}:SAM 候选 {:?},SYSTEM 候选 {:?}",
                volume.root_id(),
                sam_candidates,
                system_candidates
            ),
        );
    }
    let pick = |name: &str, candidates: &[String]| -> Result<Option<LocatedHive>> {
        for path in sources::rank_candidates(name, candidates) {
            let Some(node) = volume.stat(&path)? else {
                continue;
            };
            if !node.is_file() || node.size == 0 {
                continue;
            }
            return Ok(Some(LocatedHive {
                path,
                root_id: volume.root_id().to_string(),
                size: node.size,
                byte_len: 0,
                sha256: String::new(),
            }));
        }
        Ok(None)
    };
    Ok((pick("SAM", &sam_candidates)?, pick("SYSTEM", &system_candidates)?))
}

fn read_located(volume: &EvidenceVolume, hive: &LocatedHive) -> Result<Vec<u8>> {
    sources::read_hive(volume, &hive.path)?.ok_or_else(|| {
        lovelycarve_plugin::Error::new(
            "EVIDENCE_PATH_NOT_FOUND",
            format!("{} 在读取时消失", hive.path),
        )
    })
}

fn describe_regf_error(kind: &str, hive: &LocatedHive, error: &RegfError) -> String {
    format!(
        "{kind} hive({}, SHA-256 {}, {} 字节)解析失败:阶段 {} —— {}",
        hive.path,
        if hive.sha256.is_empty() {
            "未计算".to_string()
        } else {
            hive.sha256.clone()
        },
        hive.byte_len,
        error.stage.as_str(),
        error.message
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::md4::nt_hash_of_password;
    use crate::regf::{Hive, RegfStage};
    use crate::sam_parse::{extract, is_rid_key, HashKeys};
    use crate::testhive::*;

    fn run_system_sam(system_bytes: Vec<u8>, sam_bytes: Vec<u8>) -> crate::sam_parse::Extraction {
        let system = Hive::open(system_bytes).expect("SYSTEM parses");
        let sam = Hive::open(sam_bytes).expect("SAM parses");
        extract(&system, &sam).expect("extract")
    }

    /// 场景 1:正常账号 NT 哈希往返(已知口令 MD4(UTF16LE) → 加密写入 → 解密比对)
    #[test]
    fn normal_account_round_trip_matches_password_hash() {
        let password = "Passw0rd!测试";
        let nt = nt_hash_of_password(password);
        let sample = sample_with_account("alice", 1001, &nt, &[0u8; 16]);
        let extraction = run_system_sam(sample.system_bytes.clone(), sample.sam_bytes.clone());

        assert_eq!(extraction.bootkey.key, sample.bootkey);
        assert_eq!(extraction.accounts.len(), 1);
        let account = &extraction.accounts[0];
        assert_eq!(account.account_name, "alice");
        assert_eq!(account.rid, 1001);
        assert_eq!(account.login_count, Some(7));
        assert!(account.decrypt_ok, "reason: {:?}", account.decrypt_reason);
        assert_eq!(account.nt_hash, HashState::Present(sam_parse::hex_lower(&nt)));
        assert_eq!(account.hash_algorithm, "NT");
        assert!(account.lm_hash.hex().is_none());
    }

    /// 场景 2:空密码/禁用账号(NT 与 LM 全零)→ unavailable,不猜测
    #[test]
    fn zero_hash_is_reported_unavailable() {
        let sample = sample_with_account("disabled", 1002, &[0u8; 16], &[0u8; 16]);
        let extraction = run_system_sam(sample.system_bytes, sample.sam_bytes);
        let account = &extraction.accounts[0];
        assert_eq!(account.nt_hash.hex(), None);
        assert!(account.nt_hash.reason().expect("reason").contains("全零占位"));
        assert!(account.lm_hash.reason().expect("reason").contains("全零占位"));
    }

    /// 场景 3:仅 LM 有值、NT 长度为 0
    #[test]
    fn lm_only_account_reports_nt_unavailable() {
        let lm: [u8; 16] = [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ];
        let sample = sample_with_account("lm_user", 1003, &[0u8; 16], &lm);
        // 把 NT 长度改成 0:结构头 nt_len = 0,lm_len = 16
        let mut cipher = encrypt_user_hash(1003, &[0u8; 16], &lm, &sample.aes_key, &sample.fake);
        cipher.truncate(cipher.len());
        let mut v = v_value(&cipher, 16);
        v[0xA0..0xA4].copy_from_slice(&0u32.to_le_bytes());
        let sam_bytes = build_hive(&sam_root(
            Some(f_value_bytes(&sample.syskey)),
            vec![user_key("000003EB", user_f("lm_user", 1003, 0, 0), v)],
        ));
        let extraction = run_system_sam(sample.system_bytes, sam_bytes);
        let account = &extraction.accounts[0];
        assert_eq!(account.nt_len, Some(0));
        assert!(account.nt_hash.reason().expect("reason").contains("全零占位"));
        assert!(account.lm_hash.reason().is_some());
    }

    /// 场景 4:用户名含非 ASCII 字符
    #[test]
    fn non_ascii_account_name_is_preserved() {
        let nt = nt_hash_of_password("任意口令");
        let sample = sample_with_account("张三•测试", 1004, &nt, &[0u8; 16]);
        let extraction = run_system_sam(sample.system_bytes, sample.sam_bytes);
        assert_eq!(extraction.accounts[0].account_name, "张三•测试");
        assert_eq!(
            extraction.accounts[0].nt_hash,
            HashState::Present(sam_parse::hex_lower(&nt))
        );
    }

    /// 场景 5a:缺少 V 值
    #[test]
    fn domain_sid_and_account_sid_are_composed_from_names_default() {
        use crate::testhive::{build_hive, user_f, KeySpec};
        let mut default = vec![0u8; 0x34];
        default[0x30..0x34].copy_from_slice(&1000u32.to_le_bytes());
        default.extend_from_slice(&[1, 4, 0, 0, 0, 0, 0, 5]);
        for sub in [21u32, 1, 2, 3] {
            default.extend_from_slice(&sub.to_le_bytes());
        }
        let members = KeySpec::new("Users").child(
            KeySpec::new("000003E8").value("F", 3, user_f("alice", 1000, 0, 0)),
        );
        let names = KeySpec::new("Names").child(
            KeySpec::new("alice").value("", 3, default),
        );
        let account = KeySpec::new("Account").child(members).child(names);
        let sam = KeySpec::new("SAM").child(
            KeySpec::new("SAM").child(KeySpec::new("Domains").child(account)),
        );
        let hive = Hive::open(build_hive(&sam)).expect("SAM");
        let domain = sam_parse::domain_sid(&hive).expect("domain SID");
        assert_eq!(domain.to_string(), "S-1-5-21-1-2-3");
        let keys = sam_parse::hash_keys(&[0u8; 16], None);
        let records = sam_parse::extract_accounts(&hive, &keys).expect("accounts");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].account_sid.as_deref(), Some("S-1-5-21-1-2-3-1000"));
    }

    #[test]
    fn missing_v_value_is_reported_without_panicking() {
        let sample = sample_with_account("nov", 1005, &nt_hash_of_password("x"), &[0u8; 16]);
        let sam_bytes = build_hive(&sam_root(
            Some(f_value_bytes(&sample.syskey)),
            vec![user_key_without_v("000003ED", user_f("nov", 1005, 0, 0))],
        ));
        let extraction = run_system_sam(sample.system_bytes, sam_bytes);
        let account = &extraction.accounts[0];
        assert!(!account.decrypt_ok);
        assert!(account.nt_hash.reason().expect("reason").contains("V 值"));
        assert_eq!(account.account_name, "nov");
    }

    /// 场景 5b:截断 / hbin 越界 / magic 错误都拒解析且不崩溃
    #[test]
    fn truncated_and_out_of_range_hives_are_rejected() {
        let sample = sample_with_account("t", 1006, &nt_hash_of_password("t"), &[0u8; 16]);
        let error = Hive::open(sample.system_bytes[..100].to_vec()).expect_err("short");
        assert_eq!(error.stage, RegfStage::Header);

        let mut bytes = sample.system_bytes.clone();
        bytes[0x38..0x3C].copy_from_slice(&0x00FF_0000u32.to_le_bytes());
        let error = Hive::open(bytes).expect_err("hbins out of file");
        assert_eq!(error.stage, RegfStage::Hbin);

        let mut bytes = sample.system_bytes.clone();
        bytes[0..4].copy_from_slice(b"XXXX");
        let error = Hive::open(bytes).expect_err("bad magic");
        assert_eq!(error.stage, RegfStage::Header);

        let bytes = sample.system_bytes[..sample.system_bytes.len() - 0x800].to_vec();
        let error = Hive::open(bytes).expect_err("truncated tail");
        assert!(matches!(error.stage, RegfStage::Hbin | RegfStage::Cell));

        // 根键单元偏移越界
        let mut bytes = sample.system_bytes.clone();
        bytes[0x34..0x38].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        assert!(Hive::open(bytes).is_err());
    }

    /// 场景 6:置换顺序错误 → 解出非法哈希并被 decrypt_ok=false 捕获
    #[test]
    fn wrong_permutation_is_caught_by_aad_check() {
        let nt = nt_hash_of_password("Wr0ngPerm");
        let mut sample = sample_with_account("perm", 1007, &nt, &[0u8; 16]);
        let mut wrong = sample.bootkey;
        wrong[0] ^= 0xFF;
        sample.system_bytes = build_hive(&system_root(&lsa_classes(&wrong)));

        let extraction = run_system_sam(sample.system_bytes, sample.sam_bytes);
        assert_eq!(extraction.bootkey.key, wrong);
        let account = &extraction.accounts[0];
        assert!(!account.decrypt_ok, "{:?}", account.decrypt_reason);
        assert!(account.nt_hash.hex().is_none());
    }

    /// 场景 7:同名多账号按 RID 区分
    #[test]
    fn duplicate_names_are_distinguished_by_rid() {
        let sample = sample_with_account("same", 1008, &nt_hash_of_password("a"), &[0u8; 16]);
        let nt_a = nt_hash_of_password("a");
        let nt_b = nt_hash_of_password("b");
        let cipher_a = encrypt_user_hash(1008, &nt_a, &[0u8; 16], &sample.aes_key, &sample.fake);
        let cipher_b = encrypt_user_hash(1009, &nt_b, &[0u8; 16], &sample.aes_key, &sample.fake);
        let sam_bytes = build_hive(&sam_root(
            Some(f_value_bytes(&sample.syskey)),
            vec![
                user_key("000003F1", user_f("same", 1009, 2, 0), v_value(&cipher_b, 16)),
                user_key("000003F0", user_f("same", 1008, 1, 0), v_value(&cipher_a, 16)),
            ],
        ));
        let extraction = run_system_sam(sample.system_bytes, sam_bytes);
        assert_eq!(extraction.accounts.len(), 2);
        assert_eq!(extraction.accounts[0].rid, 1008);
        assert_eq!(extraction.accounts[1].rid, 1009);
        assert_eq!(extraction.accounts[0].nt_hash, HashState::Present(sam_parse::hex_lower(&nt_a)));
        assert_eq!(extraction.accounts[1].nt_hash, HashState::Present(sam_parse::hex_lower(&nt_b)));
    }

    /// 场景 8:SYSTEM hive 缺少 Lsa → 明确报错并带阶段
    #[test]
    fn missing_lsa_fails_with_stage() {
        let sample = sample_with_account("x", 1010, &nt_hash_of_password("x"), &[0u8; 16]);
        let system = Hive::open(build_hive(&KeySpec::new("SYSTEM"))).expect("empty SYSTEM");
        let sam = Hive::open(sample.sam_bytes).expect("SAM");
        let error = extract(&system, &sam).expect_err("must fail");
        assert!(error.contains("bootkey 派生失败"), "{error}");
        assert!(error.contains("stage="), "{error}");
        assert!(error.contains("已尝试"), "{error}");
    }

    /// 类名非法(长度/字符)时给出 signature 阶段
    #[test]
    fn malformed_class_names_fail_with_signature_stage() {
        let classes = [
            "0102030".to_string(),
            "05060708".to_string(),
            "090A0B0C".to_string(),
            "0D0E0F10".to_string(),
        ];
        let system = Hive::open(build_hive(&system_root(&classes))).expect("SYSTEM");
        let error = crate::bootkey::derive_bootkey(&system).expect_err("must fail");
        assert_eq!(error.stage, RegfStage::Signature);
    }

    /// 来源标识:SHA-256 稳定且与内容绑定
    #[test]
    fn source_identity_is_stable_and_content_bound() {
        let sample = sample_with_account("src", 1011, &nt_hash_of_password("s"), &[0u8; 16]);
        let digest = sources::sha256_hex(&sample.sam_bytes);
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, sources::sha256_hex(&sample.sam_bytes.clone()));
        assert_ne!(digest, sources::sha256_hex(&sample.system_bytes));
        let located = LocatedHive {
            path: "Windows/System32/config/SAM".to_string(),
            root_id: "part:1".to_string(),
            size: 4096,
            byte_len: 4096,
            sha256: digest.clone(),
        };
        let artifact = crate::present::account_artifact(
            &run_system_sam(sample.system_bytes, sample.sam_bytes).accounts[0],
            &LocatedHive {
                path: "Windows/System32/config/sam".to_string(),
                sha256: digest.clone(),
                ..located.clone()
            },
            &LocatedHive {
                path: "Windows/System32/config/system".to_string(),
                sha256: digest,
                ..located
            },
            "part:1",
        );
        assert_eq!(
            artifact.attributes.get("source.root"),
            Some(&Value::from("part:1"))
        );
        assert_eq!(
            artifact.attributes.get("source.sam.path"),
            Some(&Value::from("Windows/System32/config/sam"))
        );
        assert_eq!(
            artifact.attributes.get("source.paths"),
            Some(&Value::from(
                "Windows/System32/config/sam|Windows/System32/config/system"
            ))
        );
        assert_eq!(artifact.attributes.get("samhive.rid"), Some(&Value::from(1011_u64)));
    }

    /// F 值边界 + 缺 F 值
    #[test]
    fn f_value_boundaries_are_rejected_with_reason() {
        let mut f = user_f("ok", 1012, 3, 0);
        f[0x3C..0x40].copy_from_slice(&0xFFFFu32.to_le_bytes());
        assert!(sam_parse::parse_f(&f).is_err());
        let mut f = user_f("ok", 1012, 3, 0);
        f[0x40..0x42].copy_from_slice(&3u16.to_le_bytes());
        assert!(sam_parse::parse_f(&f).is_err());
        assert!(sam_parse::parse_f(&[0u8; 8]).is_err());

        let sample = sample_with_account("nof", 1013, &nt_hash_of_password("n"), &[0u8; 16]);
        let nt = nt_hash_of_password("n");
        let cipher = encrypt_user_hash(1013, &nt, &[0u8; 16], &sample.aes_key, &sample.fake);
        let sam_bytes = build_hive(&sam_root(
            Some(f_value_bytes(&sample.syskey)),
            vec![user_key_without_f("000003F5", v_value(&cipher, 16))],
        ));
        let extraction = run_system_sam(sample.system_bytes, sam_bytes);
        let account = &extraction.accounts[0];
        assert_eq!(account.rid, 1013);
        assert!(account.account_name.contains("F值不可读"));
        assert!(account.decrypt_ok);
        assert_eq!(account.nt_hash, HashState::Present(sam_parse::hex_lower(&nt)));
    }

    /// RID 键名规则
    #[test]
    fn rid_key_detection() {
        assert!(is_rid_key("000003E8"));
        assert!(is_rid_key("000003e8"));
        assert!(!is_rid_key("Names"));
        assert!(!is_rid_key("000003E"));
        assert!(!is_rid_key("000003EG"));
    }

    /// FILETIME → UTC ISO
    #[test]
    fn filetime_conversion_boundaries() {
        assert_eq!(sam_parse::filetime_to_utc(0), None);
        assert_eq!(
            sam_parse::filetime_to_utc(10_000_000),
            Some("1601-01-01T00:00:01Z".to_string())
        );
        assert_eq!(
            sam_parse::filetime_to_utc(116_444_736_000_000_000),
            Some("1970-01-01T00:00:00Z".to_string())
        );
    }

    /// F 值 RID 与控制键名不一致
    #[test]
    fn f_rid_overrides_key_name_with_limitation() {
        let sample = sample_with_account("mismatch", 1014, &nt_hash_of_password("m"), &[0u8; 16]);
        let nt = nt_hash_of_password("m");
        let cipher = encrypt_user_hash(1014, &nt, &[0u8; 16], &sample.aes_key, &sample.fake);
        let sam_bytes = build_hive(&sam_root(
            Some(f_value_bytes(&sample.syskey)),
            vec![user_key(
                "000003F6",
                user_f("mismatch", 2000, 1, 0),
                v_value(&cipher, 16),
            )],
        ));
        let extraction = run_system_sam(sample.system_bytes, sam_bytes);
        assert_eq!(extraction.accounts[0].rid, 2000);
        assert!(extraction.accounts[0]
            .limitations
            .iter()
            .any(|note| note.contains("不一致")));
    }

    /// 缺少 FakeBootKey:不猜测,标记 unavailable
    #[test]
    fn missing_fake_boot_key_marks_unavailable() {
        let sample = sample_with_account("nofk", 1015, &nt_hash_of_password("f"), &[0u8; 16]);
        let nt = nt_hash_of_password("f");
        let cipher = encrypt_user_hash(1015, &nt, &[0u8; 16], &sample.aes_key, &sample.fake);
        let sam_bytes = build_hive(&sam_root(
            None,
            vec![user_key(
                "000003F7",
                user_f("nofk", 1015, 1, 0),
                v_value(&cipher, 16),
            )],
        ));
        let system = Hive::open(sample.system_bytes).expect("SYSTEM");
        let sam = Hive::open(sam_bytes).expect("SAM");
        let bootkey = crate::bootkey::derive_bootkey(&system).expect("bootkey");
        let keys = HashKeys {
            aes_key: sam_parse::hash_keys(&bootkey.key, None).aes_key,
            fake_boot_key: None,
            notes: Vec::new(),
        };
        let accounts = sam_parse::extract_accounts(&sam, &keys).expect("accounts");
        assert_eq!(accounts.len(), 1);
        assert!(!accounts[0].decrypt_ok);
        assert!(accounts[0]
            .nt_hash
            .reason()
            .expect("reason")
            .contains("FakeBootKey"));
    }

    /// 每卷最多输出账号数的限制
    #[test]
    fn account_output_cap_is_documented() {
        assert!(MAX_ACCOUNTS < 10_000);
    }
}
