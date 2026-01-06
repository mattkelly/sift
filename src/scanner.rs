use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use walkdir::WalkDir;

use crate::analyzer::{AnalysisResult, Analyzer};
use crate::extractor::{Encoding, StringExtractor};
use crate::patterns::Category;

pub struct Scanner {
    extractor: StringExtractor,
    analyzer: Analyzer,
    recursive: bool,
}

impl Scanner {
    pub fn new(
        min_length: usize,
        encodings: Vec<Encoding>,
        category_filter: Option<Vec<Category>>,
        include_uncategorized: bool,
        recursive: bool,
    ) -> Self {
        Self {
            extractor: StringExtractor::new(min_length, encodings),
            analyzer: Analyzer::new(category_filter, include_uncategorized),
            recursive,
        }
    }

    pub fn scan_file(&self, path: &Path) -> io::Result<AnalysisResult> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len() as usize;

        let data = if file_size > 0 {
            // Use memory mapping for larger files
            if file_size > 1024 * 1024 {
                let mmap = unsafe { Mmap::map(&file)? };
                mmap.to_vec()
            } else {
                let mut data = Vec::with_capacity(file_size);
                let mut file = file;
                file.read_to_end(&mut data)?;
                data
            }
        } else {
            Vec::new()
        };

        let strings = self.extractor.extract(&data);
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .or_else(|| Some(path.to_string_lossy().to_string()));

        Ok(self.analyzer.analyze(strings, file_name, file_size))
    }

    pub fn scan_stdin(&self) -> io::Result<AnalysisResult> {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        let file_size = data.len();

        let strings = self.extractor.extract(&data);
        Ok(self.analyzer.analyze(strings, Some("<stdin>".to_string()), file_size))
    }

    pub fn scan_directory(&self, path: &Path) -> io::Result<Vec<AnalysisResult>> {
        let mut results = Vec::new();

        let walker = if self.recursive {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(1)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Skip files that are clearly not binary
            if should_skip_file(path) {
                continue;
            }

            // Try to scan, skip on error
            match self.scan_file(path) {
                Ok(result) => {
                    // Only include if we found something interesting
                    if result.categorized_count() > 0 || !result.uncategorized.is_empty() {
                        results.push(result);
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(results)
    }

    pub fn find_binary_files(&self, path: &Path) -> Vec<PathBuf> {
        let walker = if self.recursive {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(1)
        };

        walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| !should_skip_file(e.path()))
            .filter(|e| is_likely_binary(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect()
    }
}

fn should_skip_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Skip hidden files
    if name.starts_with('.') {
        return true;
    }

    // Skip known text file extensions
    let text_extensions = [
        "txt", "md", "rst", "json", "yaml", "yml", "toml", "xml", "html", "htm", "css", "js",
        "ts", "jsx", "tsx", "vue", "svelte", "py", "rb", "go", "rs", "c", "h", "cpp", "hpp",
        "java", "kt", "swift", "sh", "bash", "zsh", "fish", "ps1", "bat", "cmd", "sql", "csv",
        "log", "conf", "cfg", "ini", "env", "gitignore", "dockerignore", "editorconfig",
    ];

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if text_extensions.contains(&ext.to_lowercase().as_str()) {
            return true;
        }
    }

    false
}

fn is_likely_binary(path: &Path) -> bool {
    // Check file extension for known binary types
    let binary_extensions = [
        "exe", "dll", "so", "dylib", "a", "o", "obj", "bin", "dat", "db", "sqlite", "sqlite3",
        "class", "jar", "war", "ear", "pyc", "pyo", "wasm", "elf", "mach-o", "pe",
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "svg", "pdf", "doc", "docx",
        "xls", "xlsx", "ppt", "pptx", "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
        "mp3", "mp4", "wav", "avi", "mkv", "mov", "flac", "ogg", "webm",
    ];

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if binary_extensions.contains(&ext.to_lowercase().as_str()) {
            return true;
        }
    }

    // Check first bytes for binary content
    if let Ok(mut file) = File::open(path) {
        let mut buffer = [0u8; 8192];
        if let Ok(n) = file.read(&mut buffer) {
            if n > 0 {
                // Check for null bytes (strong indicator of binary)
                let null_count = buffer[..n].iter().filter(|&&b| b == 0).count();
                if null_count > n / 10 {
                    return true;
                }

                // Check for high proportion of non-printable characters
                let non_printable = buffer[..n]
                    .iter()
                    .filter(|&&b| b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r')
                    .count();
                if non_printable > n / 20 {
                    return true;
                }
            }
        }
    }

    // If we can't determine, assume it's not binary to avoid false positives
    false
}

/// Detect if there's likely UTF-16 content in the data
pub fn detect_utf16(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }

    // Check for BOM
    if data.starts_with(&[0xFF, 0xFE]) || data.starts_with(&[0xFE, 0xFF]) {
        return true;
    }

    // Look for null-interleaved ASCII pattern (UTF-16LE)
    // Count pairs like "a\0", "b\0", etc.
    let mut utf16le_score = 0;
    let mut utf16be_score = 0;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            // UTF-16LE: ASCII char followed by null
            if (0x20..=0x7E).contains(&chunk[0]) && chunk[1] == 0 {
                utf16le_score += 1;
            }
            // UTF-16BE: null followed by ASCII char
            if chunk[0] == 0 && (0x20..=0x7E).contains(&chunk[1]) {
                utf16be_score += 1;
            }
        }
    }

    let threshold = data.len() / 20; // 5% of data
    utf16le_score > threshold || utf16be_score > threshold
}
