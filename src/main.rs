use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process;

use clap::Parser;
use colored::Colorize;

use sift::output::{OutputFormat, OutputWriter};
use sift::scanner::Scanner;
use sift::{Category, Encoding};

#[derive(Parser)]
#[command(
    name = "sift",
    version,
    about = "Intelligent binary string extraction and analysis",
    long_about = "Extract and categorize strings from binary files. Like strings, but smarter.\n\n\
                  Automatically detects URLs, paths, UUIDs, emails, IPs, versions, dates, hashes,\n\
                  secrets (API keys, tokens), debug messages, identifiers, config values, commands,\n\
                  and other interesting strings.\n\n\
                  With no arguments, reads from stdin (if piped) or scans current directory."
)]
struct Cli {
    /// Files or directories to analyze
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Minimum string length
    #[arg(short = 'n', long, default_value = "4", value_name = "LENGTH")]
    min_length: usize,

    /// String encodings to search for (ascii, utf8, utf16, utf16le, utf16be, utf32, latin1, all)
    #[arg(short = 'e', long, value_name = "ENCODINGS", value_delimiter = ',')]
    encoding: Option<Vec<String>>,

    /// Filter by category (url, path, uuid, email, ipv4, ipv6, version, date, hash, secret, debug, ident, config, cmd, interesting)
    #[arg(short = 't', long = "type", value_name = "TYPES", value_delimiter = ',')]
    types: Option<Vec<String>>,

    /// Output format: human (default), json, summary, raw
    #[arg(short = 'o', long, default_value = "human", value_name = "FORMAT")]
    output: String,

    /// Scan directories recursively
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Show all strings, including uncategorized
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Maximum items to show per category (default: 20, 0 for unlimited)
    #[arg(long, default_value = "20", value_name = "COUNT")]
    max_items: usize,

    /// Suppress colorized output
    #[arg(long)]
    no_color: bool,
}

fn main() {
    let cli = Cli::parse();

    // Handle --no-color
    if cli.no_color {
        colored::control::set_override(false);
    }

    // Parse encodings
    let encodings = parse_encodings(&cli.encoding);

    // Parse category filter
    let category_filter = parse_categories(&cli.types);

    // Parse output format
    let output_format = match cli.output.to_lowercase().as_str() {
        "human" => OutputFormat::Human,
        "json" => OutputFormat::Json,
        "summary" => OutputFormat::Summary,
        "raw" => OutputFormat::Raw,
        other => {
            eprintln!(
                "{}: Unknown output format '{}'. Use human, json, summary, or raw.",
                "error".red().bold(),
                other
            );
            process::exit(1);
        }
    };

    // Create scanner
    let scanner = Scanner::new(
        cli.min_length,
        encodings,
        category_filter,
        cli.verbose,
        cli.recursive,
    );

    // Create output writer
    let max_items = if cli.max_items == 0 {
        None
    } else {
        Some(cli.max_items)
    };
    let writer = OutputWriter::new(output_format, max_items, cli.verbose);

    // Determine what to scan
    let results = if cli.paths.is_empty() {
        // No paths provided - check if stdin has data or scan cwd
        if !io::stdin().is_terminal() {
            // Stdin has data (piped)
            match scanner.scan_stdin() {
                Ok(result) => vec![result],
                Err(e) => {
                    eprintln!("{}: Failed to read stdin: {}", "error".red().bold(), e);
                    process::exit(1);
                }
            }
        } else {
            // Scan current directory
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            eprintln!(
                "{} {}",
                "Scanning".dimmed(),
                cwd.display().to_string().dimmed()
            );

            match scanner.scan_directory(&cwd) {
                Ok(results) => results,
                Err(e) => {
                    eprintln!(
                        "{}: Failed to scan directory: {}",
                        "error".red().bold(),
                        e
                    );
                    process::exit(1);
                }
            }
        }
    } else {
        // Scan provided paths
        let mut results = Vec::new();

        for path in &cli.paths {
            if path.is_dir() {
                match scanner.scan_directory(path) {
                    Ok(mut dir_results) => results.append(&mut dir_results),
                    Err(e) => {
                        eprintln!(
                            "{}: Failed to scan '{}': {}",
                            "warning".yellow().bold(),
                            path.display(),
                            e
                        );
                    }
                }
            } else if path.is_file() {
                match scanner.scan_file(path) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        eprintln!(
                            "{}: Failed to read '{}': {}",
                            "warning".yellow().bold(),
                            path.display(),
                            e
                        );
                    }
                }
            } else {
                eprintln!(
                    "{}: Path not found: {}",
                    "warning".yellow().bold(),
                    path.display()
                );
            }
        }

        results
    };

    // Output results
    if results.is_empty() {
        if output_format != OutputFormat::Json {
            eprintln!("{}", "No interesting strings found.".dimmed());
        } else {
            println!("[]");
        }
        return;
    }

    for result in &results {
        if let Err(e) = writer.write(result) {
            eprintln!("{}: Failed to write output: {}", "error".red().bold(), e);
            process::exit(1);
        }

        // Add separator between files if multiple
        if results.len() > 1 && output_format == OutputFormat::Human {
            println!();
        }
    }
}

fn parse_encodings(input: &Option<Vec<String>>) -> Vec<Encoding> {
    match input {
        None => Encoding::default_set(),
        Some(names) => {
            if names.iter().any(|n| n.to_lowercase() == "all") {
                return Encoding::all();
            }

            let mut encodings = Vec::new();
            for name in names {
                match Encoding::from_name(name) {
                    Some(enc) => encodings.push(enc),
                    None => {
                        eprintln!(
                            "{}: Unknown encoding '{}'. Using defaults.",
                            "warning".yellow().bold(),
                            name
                        );
                    }
                }
            }

            if encodings.is_empty() {
                Encoding::default_set()
            } else {
                encodings
            }
        }
    }
}

fn parse_categories(input: &Option<Vec<String>>) -> Option<Vec<Category>> {
    match input {
        None => None,
        Some(names) => {
            let mut categories = Vec::new();
            for name in names {
                let lower = name.to_lowercase();
                if lower == "ip" {
                    categories.push(Category::Ipv4);
                    categories.push(Category::Ipv6);
                } else if let Some(cat) = Category::from_name(&lower) {
                    categories.push(cat);
                } else {
                    eprintln!(
                        "{}: Unknown category '{}'. Ignoring.",
                        "warning".yellow().bold(),
                        name
                    );
                }
            }

            if categories.is_empty() {
                None
            } else {
                Some(categories)
            }
        }
    }
}
