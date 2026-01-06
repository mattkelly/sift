use colored::Colorize;
use num_format::{Locale, ToFormattedString};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, Write};

use crate::analyzer::{AnalysisResult, CategorizedString};
use crate::patterns::Category;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Summary,
    Raw,
}

pub struct OutputWriter {
    format: OutputFormat,
    max_items: Option<usize>,
    show_uncategorized: bool,
}

impl OutputWriter {
    pub fn new(format: OutputFormat, max_items: Option<usize>, show_uncategorized: bool) -> Self {
        Self {
            format,
            max_items,
            show_uncategorized,
        }
    }

    pub fn write(&self, result: &AnalysisResult) -> io::Result<()> {
        match self.format {
            OutputFormat::Human => self.write_human(result),
            OutputFormat::Json => self.write_json(result),
            OutputFormat::Summary => self.write_summary(result),
            OutputFormat::Raw => self.write_raw(result),
        }
    }

    fn write_human(&self, result: &AnalysisResult) -> io::Result<()> {
        let stdout = io::stdout();
        let mut out = stdout.lock();

        // Header
        if let Some(name) = &result.file_name {
            writeln!(
                out,
                "{} {}",
                name.bold(),
                format!("({})", format_size(result.file_size)).dimmed()
            )?;
        }
        writeln!(out)?;

        // Categories in a sensible order
        let order = [
            Category::Url,
            Category::Path,
            Category::Uuid,
            Category::Email,
            Category::Ipv4,
            Category::Ipv6,
            Category::Version,
            Category::Date,
            Category::Hash,
            Category::Debug,
            Category::Identifier,
            Category::Config,
            Category::Command,
            Category::Interesting,
        ];

        for category in order {
            if let Some(strings) = result.categorized.get(&category) {
                if strings.is_empty() {
                    continue;
                }
                self.write_category(&mut out, category, strings)?;
            }
        }

        // Uncategorized
        if self.show_uncategorized && !result.uncategorized.is_empty() {
            writeln!(
                out,
                " {} {}",
                "Other".bold().white(),
                format!("({})", result.uncategorized.len()).dimmed()
            )?;

            let items = match self.max_items {
                Some(max) => result.uncategorized.iter().take(max).collect::<Vec<_>>(),
                None => result.uncategorized.iter().collect::<Vec<_>>(),
            };

            for s in &items {
                writeln!(out, "   {}", truncate_string(s, 100).dimmed())?;
            }

            if let Some(max) = self.max_items {
                if result.uncategorized.len() > max {
                    writeln!(
                        out,
                        "   {}",
                        format!("... and {} more", result.uncategorized.len() - max).dimmed()
                    )?;
                }
            }
            writeln!(out)?;
        }

        // Summary line
        self.write_summary_line(&mut out, result)?;

        Ok(())
    }

    fn write_category(
        &self,
        out: &mut impl Write,
        category: Category,
        strings: &[CategorizedString],
    ) -> io::Result<()> {
        let header = format!(" {} ({})", category.name(), strings.len());
        let colored_header = match category {
            Category::Url => header.bold().blue(),
            Category::Path => header.bold().green(),
            Category::Uuid => header.bold().yellow(),
            Category::Email => header.bold().magenta(),
            Category::Ipv4 | Category::Ipv6 => header.bold().cyan(),
            Category::Version => header.bold().white(),
            Category::Date => header.bold().white(),
            Category::Hash => header.bold().red(),
            Category::Debug => header.bold().red(),
            Category::Identifier => header.bold().cyan(),
            Category::Config => header.bold().yellow(),
            Category::Command => header.bold().magenta(),
            Category::Interesting => header.bold().green(),
            Category::Other => header.bold().white(),
        };
        writeln!(out, "{}", colored_header)?;

        let items = match self.max_items {
            Some(max) => strings.iter().take(max).collect::<Vec<_>>(),
            None => strings.iter().collect::<Vec<_>>(),
        };

        for s in &items {
            let display = truncate_string(&s.value, 80);
            let colored_value = match category {
                Category::Url => display.blue(),
                Category::Path => display.green(),
                Category::Uuid => display.yellow(),
                Category::Email => display.magenta(),
                Category::Ipv4 | Category::Ipv6 => display.cyan(),
                Category::Hash => display.red(),
                Category::Debug => display.red(),
                Category::Identifier => display.cyan(),
                Category::Config => display.yellow(),
                Category::Command => display.magenta(),
                Category::Interesting => display.green(),
                _ => display.normal(),
            };

            if s.count > 1 {
                writeln!(out, "   {} {}", colored_value, format!("(x{})", s.count).dimmed())?;
            } else {
                writeln!(out, "   {}", colored_value)?;
            }
        }

        if let Some(max) = self.max_items {
            if strings.len() > max {
                writeln!(
                    out,
                    "   {}",
                    format!("... and {} more", strings.len() - max).dimmed()
                )?;
            }
        }

        writeln!(out)?;
        Ok(())
    }

    fn write_summary_line(&self, out: &mut impl Write, result: &AnalysisResult) -> io::Result<()> {
        let separator = "─".repeat(40);
        writeln!(out, "{}", separator.dimmed())?;

        let categorized = result.categorized_count();
        let percentage = if result.total_strings > 0 {
            (categorized as f64 / result.total_strings as f64) * 100.0
        } else {
            0.0
        };

        writeln!(
            out,
            "  {} {}  {} {} ({})",
            "Total:".dimmed(),
            result.total_strings.to_formatted_string(&Locale::en),
            "Categorized:".dimmed(),
            categorized.to_formatted_string(&Locale::en),
            format!("{:.1}%", percentage).dimmed()
        )?;

        // Category breakdown
        let counts = result.category_counts();
        let mut parts: Vec<String> = Vec::new();
        for cat in Category::all() {
            if let Some(&count) = counts.get(&cat) {
                if count > 0 {
                    parts.push(format!("{} {}", cat.name(), count));
                }
            }
        }

        if !parts.is_empty() {
            writeln!(out, "  {}", parts.join(" │ ").dimmed())?;
        }

        Ok(())
    }

    fn write_json(&self, result: &AnalysisResult) -> io::Result<()> {
        let output = JsonOutput::from(result);
        let json = serde_json::to_string_pretty(&output)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        println!("{}", json);
        Ok(())
    }

    fn write_summary(&self, result: &AnalysisResult) -> io::Result<()> {
        let stdout = io::stdout();
        let mut out = stdout.lock();

        if let Some(name) = &result.file_name {
            writeln!(out, "{}", name.bold())?;
        }

        let counts = result.category_counts();
        for cat in Category::all() {
            if let Some(&count) = counts.get(&cat) {
                if count > 0 {
                    writeln!(out, "  {}: {}", cat.name(), count)?;
                }
            }
        }

        writeln!(out, "  Total: {}", result.total_strings)?;
        writeln!(out, "  Categorized: {}", result.categorized_count())?;

        Ok(())
    }

    fn write_raw(&self, result: &AnalysisResult) -> io::Result<()> {
        for strings in result.categorized.values() {
            for s in strings {
                println!("{}", s.value);
            }
        }
        for s in &result.uncategorized {
            println!("{}", s);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct JsonOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    size_bytes: usize,
    strings: HashMap<String, Vec<String>>,
    stats: JsonStats,
}

#[derive(Serialize)]
struct JsonStats {
    total: usize,
    categorized: usize,
    by_category: HashMap<String, usize>,
}

impl From<&AnalysisResult> for JsonOutput {
    fn from(result: &AnalysisResult) -> Self {
        let strings: HashMap<String, Vec<String>> = result
            .categorized
            .iter()
            .map(|(cat, items)| {
                (
                    cat.name().to_lowercase(),
                    items.iter().map(|s| s.value.clone()).collect(),
                )
            })
            .collect();

        let by_category: HashMap<String, usize> = result
            .category_counts()
            .into_iter()
            .map(|(cat, count)| (cat.name().to_lowercase(), count))
            .collect();

        JsonOutput {
            file: result.file_name.clone(),
            size_bytes: result.file_size,
            strings,
            stats: JsonStats {
                total: result.total_strings,
                categorized: result.categorized_count(),
                by_category,
            },
        }
    }
}

fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
