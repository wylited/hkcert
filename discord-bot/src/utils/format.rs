use chrono::DateTime;
use std::time::{SystemTime, UNIX_EPOCH};

/// Format a timestamp in a human-readable way
pub fn format_timestamp<T: chrono::TimeZone>(dt: &DateTime<T>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Truncate a string to a maximum length with ellipsis
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Format bytes to human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_idx])
}

/// Format duration in seconds to human-readable
pub fn format_duration(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Escape Discord markdown
pub fn escape_markdown(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('~', "\\~")
        .replace('`', "\\`")
        .replace('|', "\\|")
}

/// Create a code block
pub fn code_block(language: &str, content: &str) -> String {
    format!("```{language}\n{content}\n```")
}

/// Create inline code
pub fn inline_code(content: &str) -> String {
    format!("`{content}`")
}

/// Format a list of items with bullet points
pub fn bullet_list(items: &[String]) -> String {
    items.iter().map(|i| format!("• {i}")).collect::<Vec<_>>().join("\n")
}
