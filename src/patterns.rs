use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Url,
    Path,
    Uuid,
    Email,
    Ipv4,
    Ipv6,
    Version,
    Date,
    Hash,
    Secret,
    Debug,
    Identifier,
    Config,
    Command,
    Interesting,
    Other,
}

impl Category {
    pub fn all() -> Vec<Category> {
        vec![
            Category::Url,
            Category::Path,
            Category::Uuid,
            Category::Email,
            Category::Ipv4,
            Category::Ipv6,
            Category::Version,
            Category::Date,
            Category::Hash,
            Category::Secret,
            Category::Debug,
            Category::Identifier,
            Category::Config,
            Category::Command,
            Category::Interesting,
        ]
    }

    pub fn from_name(name: &str) -> Option<Category> {
        match name.to_lowercase().as_str() {
            "url" | "urls" => Some(Category::Url),
            "path" | "paths" => Some(Category::Path),
            "uuid" | "uuids" => Some(Category::Uuid),
            "email" | "emails" => Some(Category::Email),
            "ipv4" | "ip4" => Some(Category::Ipv4),
            "ipv6" | "ip6" => Some(Category::Ipv6),
            "ip" => None, // Ambiguous - caller should handle
            "version" | "versions" | "ver" => Some(Category::Version),
            "date" | "dates" => Some(Category::Date),
            "hash" | "hashes" => Some(Category::Hash),
            "secret" | "secrets" | "token" | "tokens" | "key" | "keys" | "credential" | "credentials" => Some(Category::Secret),
            "debug" | "dbg" | "error" | "log" => Some(Category::Debug),
            "identifier" | "ident" | "id" | "symbol" | "sym" => Some(Category::Identifier),
            "config" | "cfg" | "setting" | "settings" => Some(Category::Config),
            "command" | "cmd" | "commands" => Some(Category::Command),
            "interesting" | "notable" => Some(Category::Interesting),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Category::Url => "URLs",
            Category::Path => "Paths",
            Category::Uuid => "UUIDs",
            Category::Email => "Emails",
            Category::Ipv4 => "IPv4",
            Category::Ipv6 => "IPv6",
            Category::Version => "Versions",
            Category::Date => "Dates",
            Category::Hash => "Hashes",
            Category::Secret => "Secrets",
            Category::Debug => "Debug/Errors",
            Category::Identifier => "Identifiers",
            Category::Config => "Config",
            Category::Command => "Commands",
            Category::Interesting => "Interesting",
            Category::Other => "Other",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// Compiled regex patterns
static URL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)^(https?|ftp|file)://[^\s<>"{}|\\^\[\]`]+$"#).unwrap()
});

// Unix paths: require either well-known prefix or at least 2 segments
static PATH_UNIX_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^/(usr|bin|etc|var|tmp|dev|home|opt|lib|sbin|proc|sys|run|mnt|media|boot|root|srv)/[a-zA-Z0-9._/-]+$|^(/[a-zA-Z0-9._-]+){2,}/?$").unwrap()
});

static PATH_WINDOWS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)^[a-z]:\\([^<>:"/\\|?*\x00-\x1f]+\\)*[^<>:"/\\|?*\x00-\x1f]*$"#).unwrap()
});

static PATH_RELATIVE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\./[a-zA-Z0-9._/-]+$").unwrap()
});

static UUID_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
});

static EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$").unwrap()
});

static IPV4_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap()
});

static IPV6_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|:(?::[0-9a-f]{1,4}){1,7}|::)$").unwrap()
});

static VERSION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^v?\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.-]+)?(?:\+[a-zA-Z0-9.-]+)?$").unwrap()
});

static DATE_ISO_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])(?:T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.\d+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])?)?$").unwrap()
});

static DATE_COMMON_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}$").unwrap()
});

// Hash patterns - only match standalone hex strings of specific lengths
static HASH_MD5_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{32}$").unwrap()
});

static HASH_SHA1_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{40}$").unwrap()
});

static HASH_SHA256_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{64}$").unwrap()
});

// Secret/credential patterns - API keys, tokens, etc.
// GitHub tokens
static SECRET_GITHUB_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}$").unwrap()
});

// AWS access key IDs
static SECRET_AWS_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^AKIA[0-9A-Z]{16}$").unwrap()
});

// Slack tokens
static SECRET_SLACK_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^xox[baprs]-[0-9A-Za-z-]+$").unwrap()
});

// Stripe keys
static SECRET_STRIPE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}$").unwrap()
});

// Private key markers
static SECRET_PRIVATE_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----").unwrap()
});

// JWT tokens (header.payload.signature)
static SECRET_JWT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$").unwrap()
});

// Debug/error message patterns - format strings and error keywords
static DEBUG_FORMAT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"%[-+0 #]*\d*\.?\d*[hlL]*[diouxXeEfFgGaAcspn%]").unwrap()
});

static DEBUG_KEYWORD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(error|fail(ed|ure)?|warn(ing)?|debug|assert|exception|invalid|cannot|unable|refused|timeout|denied|fatal|critical|panic|abort)\b").unwrap()
});

// Identifier patterns - function/variable names
static IDENT_CAMEL_CASE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z][a-z0-9]*([A-Z][a-z0-9]*)+$").unwrap()
});

static IDENT_PASCAL_CASE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([A-Z][a-z0-9]+){2,}$").unwrap()
});

static IDENT_SNAKE_CASE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$").unwrap()
});

static IDENT_SCREAMING_SNAKE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$").unwrap()
});

// Config patterns - key=value, JSON-like
static CONFIG_KEY_VALUE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9_.-]*\s*[=:]\s*.+$").unwrap()
});

// Command patterns - AT commands, shell-like commands
static COMMAND_AT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^AT[+#]?[A-Z]+").unwrap()
});

// Keywords that make a string interesting
static INTERESTING_KEYWORDS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(password|passwd|secret|token|key|api[_-]?key|auth|credential|private|certificate|license|serial|firmware|version|boot|init|start|stop|reset|update|download|upload|connect|disconnect|socket|port|address|server|client|request|response|header|cookie|session|user|admin|root|sudo|permission|access|allow|deny|block|filter|parse|encode|decode|encrypt|decrypt|hash|sign|verify|valid|check|test|enable|disable|on|off|true|false|yes|no|success|ok|done|ready|busy|wait|pending|queue|buffer|cache|memory|alloc|free|read|write|open|close|send|recv|get|set|put|post|delete|create|remove|add|insert|append|clear|flush|sync|async|callback|handler|hook|event|signal|interrupt|timer|delay|sleep|wake|thread|process|task|job|worker|mutex|lock|unlock|acquire|release)\b").unwrap()
});

// Rust/C++ mangled symbol patterns to exclude
static MANGLED_SYMBOL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$[A-Z]{2}\$|\$[a-z]{2}\$|::h[0-9a-f]{16}$|^_Z[A-Z]|^__Z").unwrap()
});

pub struct PatternMatcher {
    filter: Option<Vec<Category>>,
}

impl PatternMatcher {
    pub fn new(filter: Option<Vec<Category>>) -> Self {
        Self { filter }
    }

    pub fn categorize(&self, s: &str) -> Option<Category> {
        let s = s.trim();

        // Skip very short strings
        if s.len() < 3 {
            return None;
        }

        let categories_to_check = self.filter.as_ref().map_or_else(Category::all, |f| f.clone());

        for cat in categories_to_check {
            if self.matches_category(s, cat) {
                return Some(cat);
            }
        }

        None
    }

    fn matches_category(&self, s: &str, category: Category) -> bool {
        match category {
            // Quick pre-filters before expensive regex calls
            Category::Url => {
                (s.starts_with("http") || s.starts_with("ftp") || s.starts_with("file"))
                    && URL_PATTERN.is_match(s)
            }
            Category::Path => {
                (s.starts_with('/') || s.starts_with("./") || (s.len() > 2 && s.as_bytes()[1] == b':'))
                    && (PATH_UNIX_PATTERN.is_match(s)
                        || PATH_WINDOWS_PATTERN.is_match(s)
                        || PATH_RELATIVE_PATTERN.is_match(s))
            }
            Category::Uuid => {
                s.len() == 36 && s.contains('-') && UUID_PATTERN.is_match(s)
            }
            Category::Email => {
                s.contains('@') && s.contains('.') && EMAIL_PATTERN.is_match(s)
            }
            Category::Ipv4 => {
                s.len() >= 7 && s.len() <= 15 && s.contains('.')
                    && s.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && IPV4_PATTERN.is_match(s)
            }
            Category::Ipv6 => {
                s.contains(':') && IPV6_PATTERN.is_match(s)
            }
            Category::Version => {
                s.contains('.') && VERSION_PATTERN.is_match(s)
            }
            Category::Date => {
                (s.contains('-') || s.contains('/'))
                    && (DATE_ISO_PATTERN.is_match(s) || DATE_COMMON_PATTERN.is_match(s))
            }
            Category::Hash => {
                let len = s.len();
                (len == 32 || len == 40 || len == 64)
                    && s.chars().all(|c| c.is_ascii_hexdigit())
                    && (HASH_MD5_PATTERN.is_match(s)
                        || HASH_SHA1_PATTERN.is_match(s)
                        || HASH_SHA256_PATTERN.is_match(s))
            }
            Category::Secret => {
                is_potential_secret(s)
                    && (SECRET_GITHUB_PATTERN.is_match(s)
                        || SECRET_AWS_KEY_PATTERN.is_match(s)
                        || SECRET_SLACK_PATTERN.is_match(s)
                        || SECRET_STRIPE_PATTERN.is_match(s)
                        || SECRET_PRIVATE_KEY_PATTERN.is_match(s)
                        || SECRET_JWT_PATTERN.is_match(s)
                        || is_high_entropy_secret(s))
            }
            Category::Debug => {
                !is_mangled_symbol(s)
                    && !looks_like_hash(s)
                    && (s.contains('%') || has_debug_keyword(s))
                    && (DEBUG_FORMAT_PATTERN.is_match(s) || DEBUG_KEYWORD_PATTERN.is_match(s))
            }
            Category::Identifier => {
                s.len() >= 6
                    && s.len() <= 50
                    && !is_mangled_symbol(s)
                    && !looks_like_hash(s)
                    && (s.contains('_') || has_case_transition(s))
                    && (IDENT_CAMEL_CASE.is_match(s)
                        || IDENT_PASCAL_CASE.is_match(s)
                        || IDENT_SNAKE_CASE.is_match(s)
                        || IDENT_SCREAMING_SNAKE.is_match(s))
            }
            Category::Config => {
                (s.contains('=') || s.contains(':'))
                    && !is_mangled_symbol(s)
                    && CONFIG_KEY_VALUE.is_match(s)
            }
            Category::Command => {
                s.starts_with("AT") && COMMAND_AT_PATTERN.is_match(s)
            }
            Category::Interesting => {
                s.len() >= 8
                    && !is_mangled_symbol(s)
                    && has_words(s)
                    && INTERESTING_KEYWORDS.is_match(s)
            }
            Category::Other => false,
        }
    }
}

/// Quick check for debug-related keywords without regex
fn has_debug_keyword(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("error") || lower.contains("fail") || lower.contains("warn")
        || lower.contains("debug") || lower.contains("assert") || lower.contains("invalid")
}

/// Check if string has case transitions (for camelCase/PascalCase detection)
fn has_case_transition(s: &str) -> bool {
    let mut prev_lower = false;
    for c in s.chars() {
        if c.is_uppercase() && prev_lower {
            return true;
        }
        prev_lower = c.is_lowercase();
    }
    false
}

/// Check if a string looks like a mangled C++/Rust symbol
fn is_mangled_symbol(s: &str) -> bool {
    // Contains Rust mangling markers like $LT$, $GT$, $u20$, etc.
    if s.contains('$') {
        return true;
    }
    // C++ mangled names or Rust hash suffixes
    MANGLED_SYMBOL_PATTERN.is_match(s)
}

/// Check if a string looks like a hash or random hex
fn looks_like_hash(s: &str) -> bool {
    // Count hex-like characters at the end
    let hex_suffix: String = s.chars().rev().take_while(|c| c.is_ascii_hexdigit()).collect();
    // If more than 8 hex chars at the end, probably a hash
    if hex_suffix.len() >= 8 {
        return true;
    }
    // High ratio of digits to letters suggests garbage
    let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
    let letters = s.chars().filter(|c| c.is_alphabetic()).count();
    if letters > 0 && digits > letters {
        return true;
    }
    false
}

/// Quick pre-filter for potential secrets
fn is_potential_secret(s: &str) -> bool {
    let len = s.len();
    // Most tokens are 20-200 chars
    if len < 20 || len > 500 {
        return false;
    }
    // Check for common prefixes
    if s.starts_with("ghp_") || s.starts_with("gho_") || s.starts_with("ghu_")
        || s.starts_with("ghs_") || s.starts_with("ghr_") || s.starts_with("github_pat_")
        || s.starts_with("AKIA") || s.starts_with("xox")
        || s.starts_with("sk_live_") || s.starts_with("sk_test_")
        || s.starts_with("pk_live_") || s.starts_with("pk_test_")
        || s.starts_with("eyJ")  // JWT
        || s.contains("PRIVATE KEY")
    {
        return true;
    }
    // For generic secrets, check if it's mostly alphanumeric (base64-ish)
    let alphanum = s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '+' || *c == '/' || *c == '=').count();
    alphanum > len * 9 / 10
}

/// Check if string has high entropy (likely a secret key)
fn is_high_entropy_secret(s: &str) -> bool {
    let len = s.len();
    // Must be reasonable length
    if len < 28 || len > 100 {
        return false;
    }
    // Exclude paths, package names, URLs
    if s.contains('/') || s.contains('.') || s.contains("::") {
        return false;
    }
    // Exclude likely symbol names (CGO, mangled)
    if s.starts_with('_') || s.starts_with("Cfunc") || s.contains("__") {
        return false;
    }
    // Must be only alphanumeric with limited special chars
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+' || c == '=') {
        return false;
    }
    // Calculate character class diversity
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());

    // Must have mixed case AND digits (real secrets almost always do)
    if !(has_upper && has_lower && has_digit) {
        return false;
    }

    // Check digit ratio - secrets typically have 10-50% digits
    let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
    let digit_ratio = digit_count as f32 / len as f32;
    digit_ratio >= 0.10 && digit_ratio <= 0.5
}

/// Check if a string looks like it contains actual words (has spaces or mixed case)
fn has_words(s: &str) -> bool {
    // Has spaces with word-like content
    if s.contains(' ') && s.chars().filter(|c| c.is_alphabetic()).count() > s.len() / 2 {
        return true;
    }
    // Or is a reasonable identifier
    let alpha_count = s.chars().filter(|c| c.is_alphabetic()).count();
    alpha_count > 3 && alpha_count > s.len() / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_matching() {
        let matcher = PatternMatcher::new(None);
        assert_eq!(
            matcher.categorize("https://example.com/path"),
            Some(Category::Url)
        );
        assert_eq!(
            matcher.categorize("http://localhost:8080"),
            Some(Category::Url)
        );
        assert_eq!(
            matcher.categorize("ftp://files.example.com/data"),
            Some(Category::Url)
        );
    }

    #[test]
    fn test_path_matching() {
        let matcher = PatternMatcher::new(None);
        assert_eq!(matcher.categorize("/usr/local/bin"), Some(Category::Path));
        assert_eq!(
            matcher.categorize("C:\\Windows\\System32"),
            Some(Category::Path)
        );
        assert_eq!(matcher.categorize("./src/main.rs"), Some(Category::Path));
    }

    #[test]
    fn test_uuid_matching() {
        let matcher = PatternMatcher::new(None);
        assert_eq!(
            matcher.categorize("550e8400-e29b-41d4-a716-446655440000"),
            Some(Category::Uuid)
        );
    }

    #[test]
    fn test_email_matching() {
        let matcher = PatternMatcher::new(None);
        assert_eq!(
            matcher.categorize("user@example.com"),
            Some(Category::Email)
        );
    }

    #[test]
    fn test_ip_matching() {
        let matcher = PatternMatcher::new(None);
        assert_eq!(matcher.categorize("192.168.1.1"), Some(Category::Ipv4));
        assert_eq!(matcher.categorize("::1"), Some(Category::Ipv6));
        assert_eq!(
            matcher.categorize("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            Some(Category::Ipv6)
        );
    }

    #[test]
    fn test_version_matching() {
        let matcher = PatternMatcher::new(None);
        assert_eq!(matcher.categorize("1.0.0"), Some(Category::Version));
        assert_eq!(matcher.categorize("v2.1.3"), Some(Category::Version));
        assert_eq!(matcher.categorize("1.0.0-beta"), Some(Category::Version));
    }

    #[test]
    fn test_hash_matching() {
        let matcher = PatternMatcher::new(None);
        // MD5
        assert_eq!(
            matcher.categorize("d41d8cd98f00b204e9800998ecf8427e"),
            Some(Category::Hash)
        );
        // SHA1
        assert_eq!(
            matcher.categorize("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Some(Category::Hash)
        );
        // SHA256
        assert_eq!(
            matcher.categorize("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            Some(Category::Hash)
        );
    }
}
