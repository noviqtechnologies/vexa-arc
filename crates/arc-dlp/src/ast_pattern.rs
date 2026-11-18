use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AstPatternCategory {
    RawSqlInterpolation,
    DangerousEvalExec,
    RawInnerHtmlAssignment,
    PlaintextCredentialToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AstPatternFinding {
    pub category: AstPatternCategory,
    pub rule_id: String,
    pub line_number: usize,
    pub snippet: String,
    pub explanation: String,
    pub safe_alternative: String,
}

pub struct AstPatternEngine {
    ac: AhoCorasick,

    // SQL Injection patterns
    sql_fstring_double: Regex,
    sql_fstring_single: Regex,
    sql_concat_double: Regex,
    sql_concat_single: Regex,
    sql_format_re: Regex,
    sql_template_literal_re: Regex,

    // Dangerous eval / shell exec patterns
    eval_user_input_re: Regex,
    child_process_exec_re: Regex,
    os_system_concat_re: Regex,

    // Raw innerHTML patterns
    inner_html_re: Regex,

    // Plaintext private keys & tokens
    private_key_re: Regex,
    aws_key_re: Regex,
    github_pat_re: Regex,
    stripe_key_re: Regex,
    openai_key_re: Regex,
}

impl Default for AstPatternEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AstPatternEngine {
    pub fn new() -> Self {
        let keywords = vec![
            "select",
            "insert into",
            "update",
            "delete from",
            "eval",
            "child_process",
            "os.system",
            "subprocess",
            "exec",
            "innerhtml",
            "private key",
            "akia",
            "ghp_",
            "gho_",
            "ghu_",
            "ghs_",
            "sk_live",
            "rk_live",
            "sk-",
        ];

        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&keywords)
            .expect("valid aho-corasick keywords");

        Self {
            ac,
            sql_fstring_double: Regex::new(
                r#"(?i)f"[^"]*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)\b[^"]*\{[^}]+}[^"]*""#
            ).expect("valid regex"),
            sql_fstring_single: Regex::new(
                r#"(?i)f'[^']*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)\b[^']*\{[^}]+}[^']*'"#
            ).expect("valid regex"),

            sql_concat_double: Regex::new(
                r#"(?i)("[^"]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"]*"\s*\+\s*[a-zA-Z0-9_\.]+|[a-zA-Z0-9_\.]+\s*\+\s*"[^"]*\b(FROM|WHERE|VALUES)\b[^"]*")"#
            ).expect("valid regex"),
            sql_concat_single: Regex::new(
                r#"(?i)('[^']*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^']*'\s*\+\s*[a-zA-Z0-9_\.]+|[a-zA-Z0-9_\.]+\s*\+\s*'[^']*\b(FROM|WHERE|VALUES)\b[^']*')"#
            ).expect("valid regex"),

            sql_format_re: Regex::new(
                r#"(?i)(["'][^"']*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"']*["']\s*(%\s*[a-zA-Z0-9_\(\)]+|\.format\s*\())"#
            ).expect("valid regex"),

            sql_template_literal_re: Regex::new(
                r#"(?i)`[^`]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^`]*\$\{[^}]+}[^`]*`"#
            ).expect("valid regex"),

            eval_user_input_re: Regex::new(
                r#"(?i)\beval\s*\(\s*(req\.|request\.|params\.|body\.|args\.|query\.|userInput|input\b|data\.)"#
            ).expect("valid regex"),

            child_process_exec_re: Regex::new(
                r#"(?i)(child_process\.exec\s*\(\s*[`"'].*\$\{|child_process\.exec\s*\(\s*[a-zA-Z0-9_\.]+\s*\+|exec\s*\(\s*f["'].*\{|subprocess\.(Popen|run|call)\s*\(\s*f["'].*shell\s*=\s*True)"#
            ).expect("valid regex"),

            os_system_concat_re: Regex::new(
                r#"(?i)(os\.system\s*\(\s*f["'].*\{|os\.system\s*\(\s*["'][^"']*["']\s*\+)"#
            ).expect("valid regex"),

            inner_html_re: Regex::new(
                r#"(?i)\.\s*innerHTML\s*=\s*(`[^`]*\$\{[^}]+}[^`]*`|["'][^"']*["']\s*\+|[a-zA-Z0-9_\.]+\s*\+\s*|f["'][^"']*\{)"#
            ).expect("valid regex"),

            private_key_re: Regex::new(
                r#"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"#
            ).expect("valid regex"),

            aws_key_re: Regex::new(r#"\bAKIA[0-9A-Z]{16}\b"#).expect("valid regex"),
            github_pat_re: Regex::new(r#"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"#).expect("valid regex"),
            stripe_key_re: Regex::new(r#"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"#).expect("valid regex"),
            openai_key_re: Regex::new(r#"\bsk-(?:proj-)?[a-zA-Z0-9_-]{32,}\b"#).expect("valid regex"),
        }
    }

    /// Inspects the diff or content buffer of a FileWrite / FileEdit action in < 8ms,
    /// using Aho-Corasick prefiltering + Tree-sitter AST verification (JS/TS/Python)
    /// to eliminate false positives in comments and non-executable string literals.
    pub fn scan_diff(&self, content: &str) -> Vec<AstPatternFinding> {
        self.scan_diff_for_path(None, content)
    }

    pub fn scan_diff_for_path(&self, path: Option<&Path>, content: &str) -> Vec<AstPatternFinding> {
        let mut candidates: Vec<(usize, u8, AstPatternFinding)> = Vec::new();
        let bytes = content.as_bytes();
        let mut seen_categories: std::collections::HashSet<(usize, u8)> =
            std::collections::HashSet::new();

        for mat in self.ac.find_iter(bytes) {
            let offset = mat.start();
            let pat_idx = mat.pattern().as_usize();

            let category_group: u8 = match pat_idx {
                0..=3 => 1, // SQL keywords
                4..=8 => 2, // Eval / Exec
                9 => 3,     // innerHTML
                _ => 4,     // Tokens & credentials
            };

            let line_start = bytes[..offset]
                .iter()
                .rposition(|&b| b == b'\n')
                .map(|p| p + 1)
                .unwrap_or(0);
            let line_end = bytes[offset..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| offset + p)
                .unwrap_or(bytes.len());

            if seen_categories.contains(&(line_start, category_group)) {
                continue;
            }
            seen_categories.insert((line_start, category_group));

            let line = match std::str::from_utf8(&bytes[line_start..line_end]) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
                continue;
            }

            let get_line_num = || bytes[..line_start].iter().filter(|&&b| b == b'\n').count() + 1;
            let before_len = candidates.len();

            match category_group {
                1 => {
                    if let Some(m) = self
                        .sql_fstring_double
                        .find(line)
                        .or_else(|| self.sql_fstring_single.find(line))
                    {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::RawSqlInterpolation,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Unparameterized raw SQL string interpolation detected in f-string query.".to_string(),
                            safe_alternative: "Use parameterized queries with database query placeholders (e.g., cursor.execute('SELECT * FROM tbl WHERE id = %s', (val,))).".to_string(),
                        }));
                    } else if let Some(m) = self
                        .sql_concat_double
                        .find(line)
                        .or_else(|| self.sql_concat_single.find(line))
                    {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::RawSqlInterpolation,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Unparameterized SQL string concatenation detected.".to_string(),
                            safe_alternative: "Use query parameters (e.g. $1, ?, or named bind variables) rather than string concatenation.".to_string(),
                        }));
                    } else if let Some(m) = self.sql_template_literal_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::RawSqlInterpolation,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Unparameterized raw SQL interpolation detected in template literal (`SELECT ... ${var}`).".to_string(),
                            safe_alternative: "Use parameterized query helper or ORM query builder (e.g. sql`SELECT ... ${var}` with tagged template literal, or client.query(text, [var])).".to_string(),
                        }));
                    } else if let Some(m) = self.sql_format_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::RawSqlInterpolation,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Unparameterized SQL formatting detected (.format() or % operator).".to_string(),
                            safe_alternative: "Pass values as query parameters to DB driver execute() method rather than string formatting.".to_string(),
                        }));
                    }
                }
                2 => {
                    if let Some(m) = self.eval_user_input_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::DangerousEvalExec,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Direct eval() execution of user/request-controlled inputs detected.".to_string(),
                            safe_alternative: "Avoid eval(); parse input using structured parsers like JSON.parse() or dedicated domain deserializers.".to_string(),
                        }));
                    } else if let Some(m) = self.child_process_exec_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::DangerousEvalExec,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Shell command execution with interpolated parameters detected.".to_string(),
                            safe_alternative: "Use child_process.execFile() or subprocess.run(['cmd', arg]) with discrete argument arrays without shell=True.".to_string(),
                        }));
                    } else if let Some(m) = self.os_system_concat_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::DangerousEvalExec,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "os.system() call with dynamic string concatenation or f-string detected.".to_string(),
                            safe_alternative: "Use subprocess.run(['program', arg], check=True) with a list of arguments instead of os.system().".to_string(),
                        }));
                    }
                }
                3 => {
                    if let Some(m) = self.inner_html_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::RawInnerHtmlAssignment,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Raw innerHTML assignment with dynamic expression detected (potential Cross-Site Scripting).".to_string(),
                            safe_alternative: "Assign to element.textContent or element.innerText, or sanitize HTML using DOMPurify before assignment.".to_string(),
                        }));
                    }
                }
                _ => {
                    if let Some(m) = self.private_key_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::PlaintextCredentialToken,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Plaintext private key header detected in code.".to_string(),
                            safe_alternative: "Store private keys in environment variables, OS keychain, or files loaded via secret managers.".to_string(),
                        }));
                    } else if let Some(m) = self.aws_key_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::PlaintextCredentialToken,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Plaintext AWS Access Key ID detected in code.".to_string(),
                            safe_alternative: "Load AWS credentials from AWS_ACCESS_KEY_ID environment variable or ~/.aws/credentials.".to_string(),
                        }));
                    } else if let Some(m) = self.github_pat_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::PlaintextCredentialToken,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Plaintext GitHub Personal Access Token detected in code.".to_string(),
                            safe_alternative: "Read tokens from GITHUB_TOKEN environment variable rather than hardcoding.".to_string(),
                        }));
                    } else if let Some(m) = self.stripe_key_re.find(line) {
                        candidates.push((offset, category_group, AstPatternFinding {
                            category: AstPatternCategory::PlaintextCredentialToken,
                            rule_id: "ARC-AST-001".to_string(),
                            line_number: get_line_num(),
                            snippet: m.as_str().to_string(),
                            explanation: "Plaintext Stripe Live API key detected in code.".to_string(),
                            safe_alternative: "Read Stripe credentials from STRIPE_SECRET_KEY environment variable.".to_string(),
                        }));
                    } else if let Some(m) = self.openai_key_re.find(line) {
                        candidates.push((
                            offset,
                            category_group,
                            AstPatternFinding {
                                category: AstPatternCategory::PlaintextCredentialToken,
                                rule_id: "ARC-AST-001".to_string(),
                                line_number: get_line_num(),
                                snippet: m.as_str().to_string(),
                                explanation: "Plaintext OpenAI API key detected in code."
                                    .to_string(),
                                safe_alternative:
                                    "Read OpenAI keys from OPENAI_API_KEY environment variable."
                                        .to_string(),
                            },
                        ));
                    }
                }
            }
            let _ = before_len;
        }

        if candidates.is_empty() {
            return Vec::new();
        }

        // Stage 3: Tree-sitter AST verification only on candidate findings
        let lang = detect_ts_language(path, content);
        let full_tree = if bytes.len() <= 32 * 1024 {
            parse_with_tree_sitter(lang, content)
        } else {
            None
        };

        let mut findings = Vec::with_capacity(candidates.len());
        for (offset, category_group, finding) in candidates {
            let ast_ok = if let Some(ref tree) = full_tree {
                ast_allows_match(tree.root_node(), offset, category_group)
            } else {
                let win_start = floor_char_boundary(
                    content,
                    bytes[..offset.saturating_sub(1024)]
                        .iter()
                        .rposition(|&b| b == b'\n')
                        .map(|p| p + 1)
                        .unwrap_or(0),
                );
                let win_end = ceil_char_boundary(content, (offset + 1024).min(bytes.len()));
                if let Some(win_tree) = parse_with_tree_sitter(lang, &content[win_start..win_end]) {
                    ast_allows_match(
                        win_tree.root_node(),
                        offset.saturating_sub(win_start),
                        category_group,
                    )
                } else {
                    true
                }
            };
            if ast_ok {
                findings.push(finding);
            }
        }

        findings
    }

    /// Evaluates if the content contains any fatal injection patterns and returns the first violation.
    pub fn check_fatal_injection(&self, content: &str) -> Option<AstPatternFinding> {
        let findings = self.scan_diff(content);
        findings.into_iter().next()
    }

    /// Evaluates a file write/edit with language awareness from its path.
    pub fn check_fatal_injection_for_path(
        &self,
        path: Option<&Path>,
        content: &str,
    ) -> Option<AstPatternFinding> {
        self.scan_diff_for_path(path, content).into_iter().next()
    }

    /// Validates execution latency on payloads up to 256 KiB (NFR-PERF-001: sub-8ms budget)
    pub fn benchmark_latency(&self, content_size_bytes: usize) -> (std::time::Duration, usize) {
        let sample = r#"
import express from 'express';
import { db } from './db';

const router = express.Router();

// Get user profile by ID
router.get('/profile/:id', async (req, res) => {
    try {
        const userId = parseInt(req.params.id, 10);
        if (isNaN(userId)) {
            return res.status(400).json({ error: 'Invalid ID' });
        }
        const user = await db.users.findUnique({ where: { id: userId } });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

export default router;
"#;
        let repeats = (content_size_bytes / sample.len()).max(1);
        let mut buffer = sample.repeat(repeats);
        // Inject fatal injection pattern
        buffer.push_str("\nconst badQuery = `SELECT * FROM secret WHERE id = ${req.params.id}`;\n");

        let start = Instant::now();
        let findings = self.scan_diff(&buffer);
        let duration = start.elapsed();

        (duration, findings.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsLang {
    JavaScript,
    TypeScript,
    Python,
}

fn detect_ts_language(path: Option<&Path>, content: &str) -> TsLang {
    if let Some(p) = path {
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            match ext.to_ascii_lowercase().as_str() {
                "py" | "pyw" => return TsLang::Python,
                "ts" | "tsx" | "mts" | "cts" => return TsLang::TypeScript,
                "js" | "jsx" | "mjs" | "cjs" => return TsLang::JavaScript,
                _ => {}
            }
        }
    }
    let head = &content[..content.len().min(4096)];
    if head.contains("def ")
        || head.contains("os.system")
        || head.contains("subprocess.")
        || head.contains("f\"")
        || head.contains("f'")
    {
        TsLang::Python
    } else if head.contains("interface ")
        || head.contains(": string")
        || head.contains(": number")
        || head.contains(": boolean")
    {
        TsLang::TypeScript
    } else {
        TsLang::JavaScript
    }
}

fn parse_with_tree_sitter(lang: TsLang, source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    let ts_lang: Language = match lang {
        TsLang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        TsLang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        TsLang::Python => tree_sitter_python::LANGUAGE.into(),
    };
    parser.set_language(&ts_lang).ok()?;
    parser.parse(source, None)
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn ast_allows_match(root: Node<'_>, byte_offset: usize, category_group: u8) -> bool {
    let Some(mut cur) = root.descendant_for_byte_range(byte_offset, byte_offset) else {
        return true;
    };

    let mut in_string_literal = false;
    let mut in_call = false;
    let mut in_docstring = false;

    loop {
        let kind = cur.kind();
        if kind == "comment" || kind == "line_comment" || kind == "block_comment" {
            return false;
        }
        if matches!(
            kind,
            "string" | "string_fragment" | "template_string" | "string_content"
        ) {
            in_string_literal = true;
            if kind == "string"
                && cur
                    .parent()
                    .is_some_and(|p| p.kind() == "expression_statement")
            {
                in_docstring = true;
            }
        }
        if kind == "call_expression" || kind == "call" {
            in_call = true;
        }
        let Some(parent) = cur.parent() else {
            break;
        };
        cur = parent;
    }

    match category_group {
        // SQL interpolation: skip Python standalone docstrings
        1 => !in_docstring,
        // Eval / Exec: skip matches inside non-call string literals (e.g. docs/messages)
        2 => !in_string_literal || in_call,
        // innerHTML: property identifier is outside strings; skip if inside string literal
        3 => !in_string_literal,
        // Plaintext credentials: allowed inside strings, already skipped if inside comments
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ast_pattern_sql_injection_detected() {
        let engine = AstPatternEngine::new();

        let code1 = r#"
            def get_user(user_id):
                query = f"SELECT * FROM users WHERE id = {user_id}"
                cursor.execute(query)
        "#;
        let findings1 = engine.scan_diff(code1);
        assert!(!findings1.is_empty());
        assert_eq!(
            findings1[0].category,
            AstPatternCategory::RawSqlInterpolation
        );
        assert_eq!(findings1[0].rule_id, "ARC-AST-001");

        let code2 = r#"
            const q = "SELECT * FROM products WHERE name = '" + req.query.name + "'";
        "#;
        let findings2 = engine.scan_diff(code2);
        assert!(!findings2.is_empty());
        assert_eq!(
            findings2[0].category,
            AstPatternCategory::RawSqlInterpolation
        );

        let code3 = r#"
            const query = `SELECT * FROM orders WHERE user_id = ${userId}`;
        "#;
        let findings3 = engine.scan_diff(code3);
        assert!(!findings3.is_empty());
        assert_eq!(
            findings3[0].category,
            AstPatternCategory::RawSqlInterpolation
        );
    }

    #[test]
    fn test_ast_pattern_eval_and_shell_exec_detected() {
        let engine = AstPatternEngine::new();

        let code1 = r#"
            const result = eval(req.body.calculation);
        "#;
        let findings1 = engine.scan_diff(code1);
        assert!(!findings1.is_empty());
        assert_eq!(findings1[0].category, AstPatternCategory::DangerousEvalExec);

        let code2 = r#"
            child_process.exec(`ping ${host}`, (err, stdout) => {});
        "#;
        let findings2 = engine.scan_diff(code2);
        assert!(!findings2.is_empty());
        assert_eq!(findings2[0].category, AstPatternCategory::DangerousEvalExec);

        let code3 = r#"
            import os
            os.system(f"git clone {untrusted_repo}")
        "#;
        let findings3 = engine.scan_diff(code3);
        assert!(!findings3.is_empty());
        assert_eq!(findings3[0].category, AstPatternCategory::DangerousEvalExec);
    }

    #[test]
    fn test_ast_pattern_inner_html_detected() {
        let engine = AstPatternEngine::new();

        let code = r#"
            document.getElementById("profile").innerHTML = `<p>${userBio}</p>`;
        "#;
        let findings = engine.scan_diff(code);
        assert!(!findings.is_empty());
        assert_eq!(
            findings[0].category,
            AstPatternCategory::RawInnerHtmlAssignment
        );
    }

    #[test]
    fn test_ast_pattern_plaintext_credentials_detected() {
        let engine = AstPatternEngine::new();

        let code1 = r#"
            const apiKey = "AKIAIOSFODNN7EXAMPLE";
        "#;
        let findings1 = engine.scan_diff(code1);
        assert!(!findings1.is_empty());
        assert_eq!(
            findings1[0].category,
            AstPatternCategory::PlaintextCredentialToken
        );

        let stripe_dummy = format!("{}_{}_{}", "sk", "live", "51Abcdefghijklmnopqrstuvw");
        let code2 = format!("const stripeKey = \"{stripe_dummy}\";");
        let findings2 = engine.scan_diff(&code2);
        assert!(!findings2.is_empty());
        assert_eq!(
            findings2[0].category,
            AstPatternCategory::PlaintextCredentialToken
        );
    }

    #[test]
    fn test_ast_pattern_clean_code_not_flagged() {
        let engine = AstPatternEngine::new();

        let clean_code = r#"
            // Safe parameterized SQL
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            
            // Safe JSON parsing
            const data = JSON.parse(rawJson);

            // Safe DOM assignment
            element.textContent = userMessage;

            // Safe subprocess invocation
            subprocess.run(["git", "status"], check=True)
        "#;
        let findings = engine.scan_diff(clean_code);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ast_pattern_sub_8ms_latency_budget_on_256kib() {
        let engine = AstPatternEngine::new();
        // 256 KiB buffer
        let (duration, findings_count) = engine.benchmark_latency(256 * 1024);
        let threshold_ms = if cfg!(debug_assertions) { 120 } else { 8 };
        assert!(
            duration.as_millis() <= threshold_ms,
            "Diff inspection latency must be strictly under {threshold_ms} ms, got {duration:?}"
        );
        assert!(findings_count > 0);
    }

    #[test]
    fn test_tree_sitter_eliminates_false_positives_in_comments_and_strings() {
        let engine = AstPatternEngine::new();

        // 1. JS/TS multi-line block comments and documentation strings must not trigger
        let js_safe = r#"
            /*
             * Never do this in production:
             * const q = `SELECT * FROM users WHERE id = ${req.params.id}`;
             * eval(req.body.code);
             * document.body.innerHTML = `${userInput}`;
             */
            const warningDoc = "Avoid eval(req.body.x) and el.innerHTML = `${y}`";
        "#;
        assert!(
            engine
                .scan_diff_for_path(Some(Path::new("app.ts")), js_safe)
                .is_empty(),
            "Block comments and doc strings in TS must not trigger ARC-AST-001"
        );

        // 2. Python docstrings and comments must not trigger
        let py_safe = r#"
def safe_fn():
    """
    Example of unsafe code to avoid:
    os.system(f"rm -rf {path}")
    q = f"SELECT * FROM users WHERE id = {uid}"
    """
    return 42
"#;
        assert!(
            engine
                .scan_diff_for_path(Some(Path::new("app.py")), py_safe)
                .is_empty(),
            "Python docstrings must not trigger ARC-AST-001"
        );

        // 3. Comments containing fake credential headers must not trigger
        let comment_key = "// Example key: AKIAIOSFODNN7EXAMPLE\n";
        assert!(
            engine
                .scan_diff_for_path(Some(Path::new("config.js")), comment_key)
                .is_empty(),
            "Commented-out keys must not trigger ARC-AST-001"
        );
    }
}
