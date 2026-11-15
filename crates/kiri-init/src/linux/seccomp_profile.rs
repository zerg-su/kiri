//! OCI/Docker seccomp profiles compiled before clone. seccompiler supplies
//! the BPF compiler; syscall names come from generated Linux syscall tables.
//! No malformed or unsupported constraint is silently dropped.
use std::collections::BTreeMap;
use std::io;

use seccompiler::{
    BpfProgram, SeccompAction as Action, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    default_action: String,
    default_errno_ret: Option<u32>,
    #[serde(default)]
    architectures: Vec<String>,
    // Moby's architecture selection metadata. The runtime's native ABI is
    // fixed and the mandatory boundary refuses all other syscall ABIs.
    #[serde(default)]
    arch_map: Vec<serde_json::Value>,
    #[serde(default)]
    syscalls: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Rule {
    names: Vec<String>,
    action: String,
    errno_ret: Option<u32>,
    #[serde(default)]
    args: Vec<Arg>,
    #[serde(default)]
    includes: Match,
    #[serde(default)]
    excludes: Match,
    #[serde(default, rename = "comment")]
    _comment: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Match {
    #[serde(default)]
    caps: Vec<String>,
    #[serde(default)]
    arches: Vec<String>,
    min_kernel: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Arg {
    index: u8,
    value: u64,
    #[serde(default)]
    value_two: u64,
    op: String,
}

fn bad(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("seccomp profile: {message}"),
    )
}

fn action(name: &str, errno: Option<u32>) -> io::Result<Action> {
    if errno.is_some_and(|n| n > 65535) {
        return Err(bad("errno exceeds 16 bits"));
    }
    Ok(match name {
        "SCMP_ACT_ALLOW" => Action::Allow,
        "SCMP_ACT_ERRNO" => Action::Errno(errno.unwrap_or(libc::EPERM as u32)),
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => Action::KillThread,
        "SCMP_ACT_KILL_PROCESS" => Action::KillProcess,
        "SCMP_ACT_TRAP" => Action::Trap,
        "SCMP_ACT_TRACE" => Action::Trace(errno.unwrap_or(0)),
        "SCMP_ACT_LOG" => Action::Log,
        _ => return Err(bad(format!("unsupported action {name}"))),
    })
}

const CAPS: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_PTRACE",
    "SYS_PACCT",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "AUDIT_READ",
    "PERFMON",
    "BPF",
    "CHECKPOINT_RESTORE",
];

fn cap(name: &str, caps: u64) -> io::Result<bool> {
    let name = name
        .strip_prefix("CAP_")
        .ok_or_else(|| bad("capability must start with CAP_"))?;
    let bit = CAPS
        .iter()
        .position(|n| *n == name)
        .ok_or_else(|| bad(format!("unknown capability {name}")))?;
    Ok(caps & (1u64 << bit) != 0)
}

fn kernel(version: &str) -> io::Result<Vec<u32>> {
    let fields: Vec<_> = version.split('.').collect();
    if !(2..=3).contains(&fields.len()) {
        return Err(bad("invalid minKernel"));
    }
    fields
        .into_iter()
        .map(|s| s.parse().map_err(|_| bad("invalid minKernel")))
        .collect()
}

fn applies(m: &Match, caps: u64, exclude: bool) -> io::Result<bool> {
    for arch in &m.arches {
        if ![
            "amd64",
            "x32",
            "x86",
            "arm",
            "arm64",
            "mips",
            "mipsle",
            "mips64",
            "mips64le",
            "s390",
            "s390x",
            "ppc64",
            "ppc64le",
            "riscv64",
            "loong64",
            "loongarch64",
        ]
        .contains(&arch.as_str())
        {
            return Err(bad(format!("unknown architecture {arch}")));
        }
    }
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    let cap_matches = m
        .caps
        .iter()
        .map(|n| cap(n, caps))
        .collect::<io::Result<Vec<_>>>()?;
    // Moby requires every included capability, and skips a rule if any
    // excluded capability or architecture matches.
    if exclude {
        if m.min_kernel.is_some() {
            return Err(bad("excludes.minKernel is unsupported"));
        }
        return Ok(cap_matches.contains(&true) || m.arches.iter().any(|a| a == arch));
    }
    let min_kernel = if let Some(min) = &m.min_kernel {
        let min = kernel(min)?;
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
        let current = release.trim().split('-').next().unwrap_or_default();
        let mut current = kernel(current)?;
        current.resize(3, 0);
        let mut min = min;
        min.resize(3, 0);
        current >= min
    } else {
        true
    };
    Ok(cap_matches.iter().all(|v| *v)
        && (m.arches.is_empty() || m.arches.iter().any(|a| a == arch))
        && min_kernel)
}

fn syscall(name: &str) -> io::Result<Option<i64>> {
    // Linux/libseccomp calls arm64 syscall 79 newfstatat; this generated
    // table uses the libc alias fstatat. Never skip this native syscall as
    // a foreign one: that would discard its allow/deny rule.
    #[cfg(target_arch = "aarch64")]
    let name = if name == "newfstatat" { "fstatat" } else { name };
    if let Ok(n) = name.parse::<syscalls::Sysno>() {
        return Ok(Some(n as i64));
    }
    // ARM's private SWIs are outside its generated syscall table. They
    // cannot execute on either supported native ABI (aarch64/x86_64).
    // Linux v6.18 arch/arm/include/uapi/asm/unistd.h defines this closed set.
    if ["breakpoint", "cacheflush", "usr26", "usr32", "set_tls", "get_tls"].contains(&name) {
        return Ok(None);
    }
    // A portable Docker profile includes syscalls that exist only on other
    // architectures. Skip those, but reject misspellings/unknown names.
    macro_rules! known { ($($arch:ident),*) => { false $(|| name.parse::<syscalls::$arch::Sysno>().is_ok())* }; }
    if known!(
        aarch64,
        arm,
        x86,
        x86_64,
        mips,
        mips64,
        powerpc,
        powerpc64,
        s390x,
        riscv32,
        riscv64,
        loongarch64,
        sparc,
        sparc64
    ) {
        Ok(None)
    } else {
        Err(bad(format!("unknown syscall {name}")))
    }
}

fn conditions(args: &[Arg]) -> io::Result<Vec<SeccompCondition>> {
    args.iter()
        .map(|a| {
            let (op, value) = match a.op.as_str() {
                "SCMP_CMP_EQ" => (SeccompCmpOp::Eq, a.value),
                "SCMP_CMP_NE" => (SeccompCmpOp::Ne, a.value),
                "SCMP_CMP_LT" => (SeccompCmpOp::Lt, a.value),
                "SCMP_CMP_LE" => (SeccompCmpOp::Le, a.value),
                "SCMP_CMP_GT" => (SeccompCmpOp::Gt, a.value),
                "SCMP_CMP_GE" => (SeccompCmpOp::Ge, a.value),
                "SCMP_CMP_MASKED_EQ" => (SeccompCmpOp::MaskedEq(a.value), a.value_two),
                _ => return Err(bad(format!("unsupported comparison {}", a.op))),
            };
            SeccompCondition::new(a.index, SeccompCmpArgLen::Qword, op, value).map_err(bad)
        })
        .collect()
}

type Rules = BTreeMap<i64, Vec<SeccompRule>>;
fn add(rules: &mut Rules, nr: i64, args: &[SeccompCondition]) -> io::Result<()> {
    if args.is_empty() {
        rules.insert(nr, Vec::new());
    } else if !rules.get(&nr).is_some_and(Vec::is_empty) {
        rules
            .entry(nr)
            .or_default()
            .push(SeccompRule::new(args.to_vec()).map_err(bad)?);
    }
    Ok(())
}

pub fn compile(text: &str, caps: u64) -> io::Result<BpfProgram> {
    let profile: Profile = serde_json::from_str(text).map_err(bad)?;
    let native = if cfg!(target_arch = "aarch64") {
        "SCMP_ARCH_AARCH64"
    } else {
        "SCMP_ARCH_X86_64"
    };
    if !profile.architectures.is_empty() && !profile.architectures.iter().any(|a| a == native) {
        return Err(bad("profile does not include the native architecture"));
    }
    let _ = profile.arch_map;
    let fallback = action(&profile.default_action, profile.default_errno_ret)?;
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(bad)?;
    let mut all = Rules::new();
    let mut actions: Vec<(Action, Rules)> = Vec::new();
    for rule in profile.syscalls {
        let effect = action(&rule.action, rule.errno_ret)?;
        let args = conditions(&rule.args)?;
        let include = applies(&rule.includes, caps, false)?;
        let exclude = applies(&rule.excludes, caps, true)?;
        for name in rule.names {
            let nr = syscall(&name)?;
            if !include || exclude {
                continue;
            }
            let Some(nr) = nr else { continue };
            add(&mut all, nr, &args)?;
            if effect != Action::Allow {
                let at = actions
                    .iter()
                    .position(|(a, _)| *a == effect)
                    .unwrap_or_else(|| {
                        actions.push((effect.clone(), Rules::new()));
                        actions.len() - 1
                    });
                add(&mut actions[at].1, nr, &args)?;
            }
        }
    }
    let mut programs: Vec<BpfProgram> = Vec::new();
    if fallback != Action::Allow {
        programs.push(
            SeccompFilter::new(all, fallback, Action::Allow, arch)
                .map_err(bad)?
                .try_into()
                .map_err(bad)?,
        );
    }
    // The kernel chooses the most restrictive matching action. Apply that
    // precedence without installing intermediate filters that could prevent
    // the remaining seccomp syscalls from loading the rest of the policy.
    actions.sort_by_key(|(a, _)| (u32::from(a.clone()) & 0xffff_0000) as i32);
    for (effect, rules) in actions {
        programs.push(
            SeccompFilter::new(rules, Action::Allow, effect, arch)
                .map_err(bad)?
                .try_into()
                .map_err(bad)?,
        );
    }
    let mut joined = BpfProgram::new();
    let last = programs.len().saturating_sub(1);
    for (at, program) in programs.into_iter().enumerate() {
        let mut program: BpfProgram = program;
        if at != last {
            let len = program.len();
            for (i, insn) in program.iter_mut().enumerate() {
                if insn.code == 0x06 && insn.k == 0x7fff_0000 {
                    insn.code = 0x05; // BPF_JMP | BPF_JA, continue with the next filter.
                    insn.k = (len - i - 1) as u32;
                }
            }
        }
        joined.extend(program);
    }
    if joined.len() > 4096 {
        return Err(bad(
            "compiled program exceeds the kernel's 4096 instruction limit",
        ));
    }
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_newfstatat_rules_are_not_mistaken_for_a_foreign_syscall() {
        let profile = serde_json::json!({"defaultAction":"SCMP_ACT_ALLOW","syscalls":[
            {"names":["newfstatat"],"action":"SCMP_ACT_ERRNO","errnoRet":13}]});
        call(profile, libc::SYS_newfstatat, 0, Some(13), 0);
    }

    #[test]
    fn portable_profiles_may_name_foreign_arm_private_calls() {
        let text = r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["breakpoint","cacheflush","usr26","usr32","set_tls","get_tls"],"action":"SCMP_ACT_ERRNO"}]}"#;
        assert!(compile(text, 0).unwrap().is_empty(), "foreign ABI calls cannot run natively");
        assert!(syscall("breakpiont").is_err(), "a typo is still rejected");
    }

    /// The kernel, in a disposable child, is the verifier for comparisons
    /// and joined-program jumps. No test changes its own process's filter.
    fn call(
        profile: serde_json::Value,
        nr: libc::c_long,
        arg: u64,
        expected_errno: Option<i32>,
        caps: u64,
    ) {
        let filter = compile(&profile.to_string(), caps).unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if !filter.is_empty() && seccompiler::apply_filter(&filter).is_err() {
                unsafe { libc::_exit(97) };
            }
            let result = unsafe { libc::syscall(nr, arg, 0 as libc::c_long, 0 as libc::c_long,
                0 as libc::c_long, 0 as libc::c_long, 0 as libc::c_long) };
            let ok = match expected_errno {
                Some(errno) => {
                    result == -1 && io::Error::last_os_error().raw_os_error() == Some(errno)
                }
                None => result >= 0,
            };
            unsafe { libc::_exit(if ok { 0 } else { 98 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            status, 0,
            "filtered syscall did not have the requested behavior"
        );
    }

    #[test]
    fn custom_errno_and_64_bit_argument_conditions_reach_the_kernel() {
        use serde_json::json;
        for op in ["SCMP_CMP_EQ", "SCMP_CMP_MASKED_EQ"] {
            let arg = if op == "SCMP_CMP_EQ" {
                json!({"index":0,"op":op,"value":0})
            } else {
                json!({"index":0,"op":op,"value":1,"valueTwo":0})
            };
            let profile = json!({"defaultAction":"SCMP_ACT_ALLOW", "syscalls":[
                {"names":["getpgid"],"action":"SCMP_ACT_ERRNO","errnoRet":13,"args":[arg]}]});
            call(profile.clone(), libc::SYS_getpgid, 0, Some(13), 0);
            call(profile, libc::SYS_getpgid, 1, None, 0);
        }
    }

    #[test]
    fn default_deny_exceptions_and_distinct_errno_actions_are_one_filter() {
        use serde_json::json;
        let profile = json!({"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"syscalls":[
            {"names":["exit","exit_group"],"action":"SCMP_ACT_ALLOW"},
            {"names":["getppid"],"action":"SCMP_ACT_ERRNO","errnoRet":38}]});
        call(profile, libc::SYS_getppid, 0, Some(38), 0);
    }

    #[test]
    fn capability_constraints_apply_to_the_container_not_the_guest_agent() {
        use serde_json::json;
        let profile = json!({"defaultAction":"SCMP_ACT_ALLOW","syscalls":[
            {"names":["getppid"],"action":"SCMP_ACT_ERRNO","errnoRet":13,"includes":{"caps":["CAP_SYS_ADMIN"]}}]});
        call(profile.clone(), libc::SYS_getppid, 0, None, 0);
        call(profile, libc::SYS_getppid, 0, Some(13), 1 << 21);
    }

    #[test]
    fn malformed_constraints_and_unknown_features_fail_closed() {
        for text in [
            r#"{}"#,
            r#"{"defaultAction":"SCMP_ACT_NOTIFY"}"#,
            r#"{"defaultAction":"SCMP_ACT_ALLOW","flags":["ignored"]}"#,
            r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["typo_syscall"],"action":"SCMP_ACT_ALLOW"}]}"#,
            r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["getpid"],"action":"SCMP_ACT_ALLOW","args":[{"index":6,"op":"SCMP_CMP_EQ","value":0}]}]}"#,
        ] {
            assert!(compile(text, 0).is_err(), "{text}");
        }
    }
}
