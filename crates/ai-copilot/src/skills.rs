//! Skill 管理（rssh `src-tauri/src/ai/skills.rs` 移植，去掉 DB 依赖）。
//!
//! rssh 的技能放在 SQLite 里，由 Tauri 命令层 CRUD；FengheShell 没有 DB，
//! 用户自定义 Skill 改由配置文件的 `ai_skills` 字段承载（见
//! `src/config/struct/config_file.rs`），宿主每次 ask() 时快照进
//! `CopilotConfig::skills` —— 与会话启动时 snapshot cache 同语义：
//! 会话期内不变，用户中途改 skill 不影响正在跑的轮次。
//!
//! 内置 `general` 规则集（`prompts/general.md`）**直接展开**进 system prompt；
//! 用户 Skill 只在目录里放 id + 一句话描述，用 `load_skill(<id>)` 按需加载。

use serde::{Deserialize, Serialize};

/// 一条 Skill：内置 `general` 或用户自定义。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillRecord {
    pub id: String,
    pub name: String,
    pub description: String,
    pub content: String,
    /// 内置 skill（目前只有 `general`）；内置的不可删除、不可覆盖。
    #[serde(default)]
    pub builtin: bool,
}

/// 内置通用规则集的 id。它已经在 system prompt 里展开，不允许再 load。
pub const GENERAL_ID: &str = "general";

const GENERAL_NAME: &str = "General Ops diagnosis";
const GENERAL_DESC: &str = "Default rule set + workflow reference for CPU / memory / general triage. The LLM picks commands itself.";

/// 内置 `general` 规则集（编译期内嵌 prompts/general.md）。
pub fn builtin_general() -> SkillRecord {
    SkillRecord {
        id: GENERAL_ID.into(),
        name: GENERAL_NAME.into(),
        description: GENERAL_DESC.into(),
        content: crate::triage::SYSTEM_PROMPT.to_string(),
        builtin: true,
    }
}

/// 该 id 是否是内置 skill。
pub fn is_builtin(id: &str) -> bool {
    id == GENERAL_ID
}

/// 解析一次 `load_skill(id)`：只允许加载用户自定义 skill。
///
/// `general` 显式拒绝 —— 它已经在 system prompt 里，重复加载只是浪费 token
/// （rssh 同款约束）。
pub fn resolve_loadable(id: &str, user_skills: &[SkillRecord]) -> Result<SkillRecord, String> {
    if id == GENERAL_ID {
        return Err(
            "'general' is already active in the system prompt and must not be loaded again.".into(),
        );
    }
    user_skills
        .iter()
        .find(|skill| skill.id == id)
        .cloned()
        .ok_or_else(|| {
            let available = user_skills
                .iter()
                .map(|skill| skill.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            format!("Unknown skill id: {id}. Available loadable skills: [{available}]")
        })
}

/// system prompt 末尾追加的「Available skills」目录段。
/// 没有用户 skill 时返回空串（不出现目录，`load_skill` 也不进工具列表）。
pub fn catalog_section(user_skills: &[SkillRecord]) -> String {
    if user_skills.is_empty() {
        return String::new();
    }
    let mut s = String::from("\n\n---\n\n# Available skills (catalog)\n\n");
    s.push_str(
        "The `general` skill is already active. The skills below are lazy-loaded: \
         when one matches the current problem, call `load_skill(<id>)` before following it.\n\n",
    );
    for skill in user_skills {
        let desc = if skill.description.is_empty() {
            "(no description)"
        } else {
            &skill.description
        };
        s.push_str(&format!(
            "- **{}** (id: `{}`) — {}\n",
            skill.name, skill.id, desc
        ));
    }
    s
}

/// load_skill 成功时回给 LLM 的完整内容（skill 是用户自己写的可信文本，
/// 不脱敏）。
pub fn loaded_content(skill: &SkillRecord) -> String {
    format!(
        "# {} (id: {})\n\n_{}_\n\n---\n\n{}",
        skill.name, skill.id, skill.description, skill.content
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_skill() -> SkillRecord {
        SkillRecord {
            id: "user-mysql".into(),
            name: "MySQL slow query".into(),
            description: "慢查询排查流程".into(),
            content: "1. show full processlist".into(),
            builtin: false,
        }
    }

    #[test]
    fn builtin_general_is_marked_and_not_loadable() {
        let general = builtin_general();
        assert!(general.builtin);
        assert!(is_builtin(&general.id));
        let err = resolve_loadable(GENERAL_ID, &[]).unwrap_err();
        assert!(err.contains("already active"), "got: {err}");
    }

    #[test]
    fn resolves_user_skill_by_id() {
        let skill = resolve_loadable("user-mysql", &[user_skill()]).unwrap();
        assert_eq!(skill.name, "MySQL slow query");
        assert!(loaded_content(&skill).contains("show full processlist"));
    }

    #[test]
    fn unknown_id_lists_available_skills() {
        let err = resolve_loadable("user-nope", &[user_skill()]).unwrap_err();
        assert!(err.contains("Unknown skill id"), "got: {err}");
        assert!(err.contains("user-mysql"), "got: {err}");
    }

    #[test]
    fn catalog_is_empty_without_user_skills() {
        assert!(catalog_section(&[]).is_empty());
    }

    #[test]
    fn catalog_lists_user_skills_only() {
        let section = catalog_section(&[user_skill()]);
        assert!(section.contains("# Available skills (catalog)"));
        assert!(section.contains("user-mysql"));
        assert!(section.contains("慢查询排查流程"));
        // general 只以「已激活」的形式出现，不列为可加载项
        assert!(!section.contains("- **General Ops diagnosis"));
    }

    #[test]
    fn catalog_handles_empty_description() {
        let mut skill = user_skill();
        skill.description = String::new();
        assert!(catalog_section(&[skill]).contains("(no description)"));
    }
}
