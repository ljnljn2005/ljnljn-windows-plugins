//! Windows registry forensics (LPP v2): SAM accounts and NT/LM hashes,
//! SOFTWARE system version, Uninstall entries, USBSTOR devices and the SAM
//! password policy.
//!
//! The SAM analyzer pairs `SAM` and `SYSTEM` hives by volume: the bootkey is
//! derived from the SYSTEM `Lsa` class names and the account hashes are
//! decrypted from SAM. Evidence-scope pairing is the primary form; a system
//! scope variant runs on one detected Windows system. The four single-hive
//! capabilities also have file-scope analyzers for hives the examiner
//! selected explicitly.
//!
//! NT hashes stay hashes: they are emitted as lowercase MD4 hex in `hash`
//! fields, never as plaintext. Zero placeholders, unsaved LM hashes and
//! decryption failures are marked with an explicit state and reason instead
//! of a guessed value. FILETIME values (key last-write, account last login)
//! are rendered as UTC; no local time zone is inferred.

#[allow(dead_code)]
mod bootkey;
#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod regf;
mod registry;
#[allow(dead_code)]
mod sam_parse;
#[allow(dead_code)]
mod sid;
#[cfg(test)]
mod testhive;
#[cfg(test)]
mod tests;
mod time;

use std::collections::BTreeMap;

use lovelycarve_plugin::{export_plugin, FileRef, Plugin, Record, Result, Run, Timestamp};

use crate::regf::Hive;
use crate::sam_parse::{AccountRecord, HashState};

/// Most accounts emitted per hive.
const MAX_ACCOUNTS_PER_HIVE: usize = 5_000;

#[derive(Record)]
#[record(id = "windows.sam.account", label = "SAM 账号与哈希", title = "{name} ({rid})")]
struct SamAccountRecord {
    #[field(label = "账号名", key)]
    name: String,
    #[field(label = "RID", key)]
    rid: i64,
    #[field(label = "SID")]
    sid: Option<String>,
    #[field(label = "用户键")]
    user_key: String,
    #[field(label = "用户键路径")]
    user_key_path: String,
    #[field(label = "NT 哈希", kind = "hash")]
    nt_hash: Option<String>,
    #[field(
        label = "NT 状态",
        kind = "enum",
        choices = "present=可用,zero_placeholder=全零占位,unavailable=不可用,not_saved=未保存"
    )]
    nt_state: String,
    #[field(label = "NT 说明")]
    nt_reason: Option<String>,
    #[field(label = "LM 哈希", kind = "hash")]
    lm_hash: Option<String>,
    #[field(
        label = "LM 状态",
        kind = "enum",
        choices = "present=可用,zero_placeholder=全零占位,unavailable=不可用,not_saved=未保存"
    )]
    lm_state: String,
    #[field(label = "LM 说明")]
    lm_reason: Option<String>,
    #[field(
        label = "哈希算法",
        kind = "enum",
        choices = "nt=NT,lm=LM,none=无"
    )]
    hash_algorithm: String,
    #[field(label = "登录次数")]
    login_count: Option<i64>,
    #[field(label = "最后登录", timeline = "login")]
    last_login: Option<Timestamp>,
    #[field(label = "最后登录 FILETIME")]
    last_login_raw: Option<i64>,
    #[field(label = "解密校验")]
    decrypt_ok: bool,
    #[field(label = "解密说明")]
    decrypt_reason: Option<String>,
    #[field(label = "F 值 RID")]
    f_rid: Option<i64>,
    #[field(label = "NT 偏移")]
    nt_offset: Option<i64>,
    #[field(label = "NT 长度")]
    nt_len: Option<i64>,
    #[field(label = "LM 偏移")]
    lm_offset: Option<i64>,
    #[field(label = "LM 长度")]
    lm_len: Option<i64>,
    #[field(label = "限制与说明")]
    limitations: Vec<String>,
}

#[derive(Record)]
#[record(id = "windows.sam.bootkey", label = "SAM bootkey 派生", title = "{base_path}")]
struct SamBootkeyRecord {
    #[field(label = "Lsa 路径", key)]
    base_path: String,
    #[field(label = "bootkey", kind = "hash")]
    bootkey: String,
    #[field(label = "置换前数据", kind = "hash")]
    permuted: String,
    #[field(label = "类名")]
    classes: String,
    #[field(label = "类名单元")]
    class_cells: String,
    #[field(label = "限制与说明")]
    limitations: Vec<String>,
}

#[derive(Record)]
#[record(
    id = "windows.software.version",
    label = "SOFTWARE 系统版本",
    title = "{product_name}"
)]
struct SoftwareVersionRecord {
    #[field(label = "产品名称", key)]
    product_name: String,
    #[field(label = "当前版本")]
    current_version: Option<String>,
    #[field(label = "当前构建")]
    current_build: Option<String>,
    #[field(label = "构建号")]
    current_build_number: Option<String>,
    #[field(label = "CSD 版本")]
    csd_version: Option<String>,
    #[field(label = "BuildLabEx")]
    build_lab_ex: Option<String>,
    #[field(label = "InstallDate 原值")]
    install_date: Option<String>,
}

#[derive(Record)]
#[record(id = "windows.registry.uninstall", label = "Uninstall 安装项", title = "{name}")]
struct UninstallRecord {
    #[field(label = "显示名称", key)]
    name: String,
    #[field(label = "安装项键")]
    key: String,
    #[field(label = "显示版本")]
    display_version: Option<String>,
    #[field(label = "发布者")]
    publisher: Option<String>,
    #[field(label = "InstallDate 原值")]
    install_date: Option<String>,
    #[field(label = "安装位置")]
    install_location: Option<String>,
    #[field(label = "键最后写入", timeline = "modified")]
    key_last_write: Option<Timestamp>,
    #[field(label = "WOW6432Node")]
    wow64: bool,
}

#[derive(Record)]
#[record(
    id = "windows.registry.usbstor",
    label = "USB 存储设备",
    title = "{device} / {instance}"
)]
struct UsbDeviceRecord {
    #[field(label = "设备键", key)]
    device: String,
    #[field(label = "实例键", key)]
    instance: String,
    #[field(label = "设备名称")]
    friendly_name: Option<String>,
    #[field(label = "设备描述")]
    device_desc: Option<String>,
    #[field(label = "驱动服务")]
    service: Option<String>,
    #[field(label = "容器 ID")]
    container_id: Option<String>,
    #[field(label = "硬件 ID")]
    hardware_id: Option<String>,
    #[field(label = "首次安装")]
    first_install: Option<Timestamp>,
    #[field(label = "最后接入")]
    last_arrival: Option<Timestamp>,
    #[field(label = "设备键最后写入", timeline = "modified")]
    device_last_write: Option<Timestamp>,
    #[field(label = "实例键最后写入", timeline = "modified")]
    instance_last_write: Option<Timestamp>,
}

#[derive(Record)]
#[record(
    id = "windows.registry.policy",
    label = "SAM 密码策略",
    title = "MaxPasswordAge"
)]
struct SamPolicyRecord {
    #[field(label = "原始 100ns")]
    max_password_age_raw: i64,
    #[field(label = "最长留存期（秒）")]
    max_password_age_seconds: Option<i64>,
    #[field(label = "最长留存期（天）")]
    max_password_age_days: Option<i64>,
    #[field(
        label = "状态",
        kind = "enum",
        choices = "set=已设置,never_or_unset=未设置或永不过期"
    )]
    state: String,
}

fn hash_state(state: &HashState) -> (String, Option<String>) {
    match state {
        HashState::Present(_) => ("present".to_owned(), None),
        HashState::Unavailable(reason)
            if reason.starts_with("空密码") || reason.contains("哈希全零占位") =>
        {
            ("zero_placeholder".to_owned(), Some(reason.clone()))
        }
        HashState::Unavailable(reason) if reason.contains("未保存") => {
            ("not_saved".to_owned(), Some(reason.clone()))
        }
        HashState::Unavailable(reason) => ("unavailable".to_owned(), Some(reason.clone())),
    }
}

fn sam_accounts(run: &Run) -> Result<()> {
    let inputs = run.inputs();
    if inputs.is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "未找到 SAM/SYSTEM hive 输入（按清单 inputs 解析；SAM 账号需要同一卷上的两份 hive）",
        )?;
        run.set_summary("未找到可配对的 SAM/SYSTEM hive");
        return Ok(());
    }

    let mut pairs: BTreeMap<String, (Option<&FileRef>, Option<&FileRef>)> = BTreeMap::new();
    for file in inputs {
        let root = file.root().unwrap_or_default().to_owned();
        let entry = pairs.entry(root).or_default();
        match file.name().to_ascii_uppercase().as_str() {
            "SAM" => entry.0 = Some(file),
            "SYSTEM" => entry.1 = Some(file),
            _ => {}
        }
    }

    let mut paired = 0_usize;
    let mut accounts = 0_usize;
    let mut decrypted = 0_usize;
    let mut notes: Vec<String> = Vec::new();
    for (index, (root, pair)) in pairs.iter().enumerate() {
        run.check_cancelled()?;
        run.progress(
            index as u64,
            Some(pairs.len() as u64),
            Some(&format!("解析卷 {root} 的 SAM/SYSTEM")),
        )?;
        let (Some(sam), Some(system)) = (pair.0, pair.1) else {
            let missing = if pair.0.is_none() { "SAM" } else { "SYSTEM" };
            let present = if missing == "SAM" { "SYSTEM" } else { "SAM" };
            run.warn(
                if missing == "SAM" {
                    "MISSING_SAM_HIVE"
                } else {
                    "MISSING_SYSTEM_HIVE"
                },
                format!(
                    "卷 {root}: 找到 {present} 但缺少 {missing} hive，无法完成 bootkey 派生与账号提取"
                ),
            )?;
            notes.push(format!("卷 {root}: 缺少 {missing}"));
            continue;
        };
        let Some(sam_hive) = registry::read_hive(run, sam)? else {
            continue;
        };
        let Some(system_hive) = registry::read_hive(run, system)? else {
            continue;
        };
        paired += 1;
        let extraction = match sam_parse::extract(&system_hive, &sam_hive) {
            Ok(extraction) => extraction,
            Err(reason) => {
                run.warn_file(
                    sam,
                    "SAM_EXTRACTION_FAILED",
                    format!("卷 {root}: {reason}"),
                )?;
                notes.push(format!("卷 {root}: 提取失败"));
                continue;
            }
        };
        let classes = extraction
            .bootkey
            .class_sources
            .iter()
            .map(|source| format!("{}={}", source.subkey, source.class_name))
            .collect::<Vec<_>>()
            .join(",");
        let cells = extraction
            .bootkey
            .class_sources
            .iter()
            .map(|source| format!("{}@0x{:x}", source.subkey, source.cell))
            .collect::<Vec<_>>()
            .join(",");
        run.record(&SamBootkeyRecord {
            base_path: extraction.bootkey.base_path.join("\\"),
            bootkey: sam_parse::hex_lower(&extraction.bootkey.key),
            permuted: sam_parse::hex_lower(&extraction.bootkey.permuted),
            classes,
            class_cells: cells,
            limitations: extraction.limitations.clone(),
        })
        .from(system)
        .source(sam.source())
        .emit()?;

        for account in extraction.accounts.iter().take(MAX_ACCOUNTS_PER_HIVE) {
            run.check_cancelled()?;
            let (nt_state, nt_reason) = hash_state(&account.nt_hash);
            let (lm_state, lm_reason) = hash_state(&account.lm_hash);
            if account.decrypt_ok {
                decrypted += 1;
            }
            run.record(&account_record(account, nt_state, nt_reason, lm_state, lm_reason))
                .from(sam)
                .source(system.source())
                .note(format!(
                    "SAM\\Domains\\Account\\Users\\{}",
                    account.user_key_name
                ))
                .emit()?;
            accounts += 1;
        }
        if extraction.accounts.len() > MAX_ACCOUNTS_PER_HIVE {
            run.warn_file(
                sam,
                "SAM_ACCOUNT_LIMIT",
                format!(
                    "卷 {root}: 账号数 {} 超过单卷输出上限 {MAX_ACCOUNTS_PER_HIVE}，其余未输出",
                    extraction.accounts.len()
                ),
            )?;
        }
        notes.push(format!("卷 {root}: 账号 {}", extraction.accounts.len()));
    }

    if paired == 0 {
        run.warn(
            "NO_SAM_SYSTEM_PAIR",
            "没有任何卷同时提供 SAM 与 SYSTEM hive，账号哈希未提取",
        )?;
    }
    let mut summary = format!(
        "SAM/SYSTEM 配对 {paired} 组；账号 {accounts} 个，解密校验通过 {decrypted} 个"
    );
    if !notes.is_empty() {
        summary.push_str("；");
        summary.push_str(&notes.join("；"));
    }
    run.set_summary(summary);
    Ok(())
}

fn account_record(
    account: &AccountRecord,
    nt_state: String,
    nt_reason: Option<String>,
    lm_state: String,
    lm_reason: Option<String>,
) -> SamAccountRecord {
    SamAccountRecord {
        name: account.account_name.clone(),
        rid: i64::from(account.rid),
        sid: account.account_sid.clone(),
        user_key: account.user_key_name.clone(),
        user_key_path: account.user_key_path.clone(),
        nt_hash: account.nt_hash.hex().map(str::to_owned),
        nt_state,
        nt_reason,
        lm_hash: account.lm_hash.hex().map(str::to_owned),
        lm_state,
        lm_reason,
        hash_algorithm: if account.nt_hash.hex().is_some() {
            "nt"
        } else if account.lm_hash.hex().is_some() {
            "lm"
        } else {
            "none"
        }
        .to_owned(),
        login_count: account.login_count.map(i64::from),
        last_login: account
            .last_login_filetime
            .and_then(time::filetime_timestamp),
        last_login_raw: account
            .last_login_filetime
            .and_then(|raw| i64::try_from(raw).ok()),
        decrypt_ok: account.decrypt_ok,
        decrypt_reason: account.decrypt_reason.clone(),
        f_rid: account.f_rid.map(i64::from),
        nt_offset: account.nt_offset.map(i64::from),
        nt_len: account.nt_len.map(i64::from),
        lm_offset: account.lm_offset.map(i64::from),
        lm_len: account.lm_len.map(i64::from),
        limitations: account.limitations.clone(),
    }
}

fn analyze_single(
    run: &Run,
    what: &str,
    analyze: impl Fn(&Run, &FileRef, &Hive) -> Result<Option<String>>,
) -> Result<()> {
    let inputs = run.inputs();
    if inputs.is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            format!("未找到声明输入的 hive（{what}）"),
        )?;
        run.set_summary(format!("{what}: 未找到输入"));
        return Ok(());
    }
    let mut hives = 0_usize;
    let mut notes = Vec::new();
    for file in inputs {
        run.check_cancelled()?;
        let Some(hive) = registry::read_hive(run, file)? else {
            continue;
        };
        hives += 1;
        if let Some(note) = analyze(run, file, &hive)? {
            notes.push(note);
        }
    }
    if hives == 0 {
        run.warn(
            "NO_USABLE_HIVE",
            format!("{what}: {} 个输入中没有可解析的主 hive", inputs.len()),
        )?;
    }
    let mut summary = format!("{what}: 输入 {} 个，可用 hive {hives} 个", inputs.len());
    if !notes.is_empty() {
        summary.push_str("；");
        summary.push_str(&notes.join("；"));
    }
    run.set_summary(summary);
    Ok(())
}

fn software_version(run: &Run) -> Result<()> {
    analyze_single(run, "SOFTWARE 系统版本", registry::analyze_version)
}

fn uninstall(run: &Run) -> Result<()> {
    analyze_single(run, "Uninstall 安装项", registry::analyze_uninstall)
}

fn usbstor(run: &Run) -> Result<()> {
    analyze_single(run, "USBSTOR 设备", registry::analyze_usbstor)
}

fn password_policy(run: &Run) -> Result<()> {
    analyze_single(run, "SAM 密码策略", registry::analyze_policy)
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.windows-registry")
        .record::<SamAccountRecord>()
        .record::<SamBootkeyRecord>()
        .record::<SoftwareVersionRecord>()
        .record::<UninstallRecord>()
        .record::<UsbDeviceRecord>()
        .record::<SamPolicyRecord>()
        .analyzer("sam_accounts", sam_accounts)
        .analyzer("sam_accounts_system", sam_accounts)
        .analyzer("software_version", software_version)
        .analyzer("software_version_file", software_version)
        .analyzer("uninstall", uninstall)
        .analyzer("uninstall_file", uninstall)
        .analyzer("usbstor", usbstor)
        .analyzer("usbstor_file", usbstor)
        .analyzer("password_policy", password_policy)
        .analyzer("password_policy_file", password_policy)
}

export_plugin!(plugin);
