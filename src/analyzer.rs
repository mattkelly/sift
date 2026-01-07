use std::collections::HashMap;

use rayon::prelude::*;

use crate::extractor::ExtractedString;
use crate::patterns::{Category, PatternMatcher};

#[derive(Debug, Clone)]
pub struct CategorizedString {
    pub value: String,
    pub category: Category,
    pub count: usize,
}

#[derive(Debug)]
pub struct AnalysisResult {
    pub file_name: Option<String>,
    pub file_size: usize,
    pub categorized: HashMap<Category, Vec<CategorizedString>>,
    pub uncategorized: Vec<String>,
    pub total_strings: usize,
}

impl AnalysisResult {
    pub fn categorized_count(&self) -> usize {
        self.categorized.values().map(|v| v.len()).sum()
    }

    pub fn category_counts(&self) -> HashMap<Category, usize> {
        self.categorized
            .iter()
            .map(|(k, v)| (*k, v.len()))
            .collect()
    }
}

pub struct Analyzer {
    matcher: PatternMatcher,
    include_uncategorized: bool,
}

impl Analyzer {
    pub fn new(filter: Option<Vec<Category>>, include_uncategorized: bool) -> Self {
        Self {
            matcher: PatternMatcher::new(filter),
            include_uncategorized,
        }
    }

    pub fn analyze(
        &self,
        strings: Vec<ExtractedString>,
        file_name: Option<String>,
        file_size: usize,
    ) -> AnalysisResult {
        let total_strings = strings.len();

        // Step 1: Deduplicate strings and count occurrences BEFORE pattern matching
        let mut string_counts: HashMap<String, usize> = HashMap::new();
        for s in strings {
            let value = s.value.trim().to_string();
            if !value.is_empty() {
                *string_counts.entry(value).or_insert(0) += 1;
            }
        }

        // Step 2: Categorize unique strings in parallel
        let unique_strings: Vec<(String, usize)> = string_counts.into_iter().collect();
        let categorized_results: Vec<(String, usize, Option<Category>)> = unique_strings
            .into_par_iter()
            .map(|(value, count)| {
                let category = self.matcher.categorize(&value);
                (value, count, category)
            })
            .collect();

        // Step 3: Collect results into categories
        let mut categorized: HashMap<Category, HashMap<String, usize>> = HashMap::new();
        let mut uncategorized: HashMap<String, usize> = HashMap::new();

        for (value, count, category) in categorized_results {
            if let Some(cat) = category {
                categorized
                    .entry(cat)
                    .or_default()
                    .insert(value, count);
            } else if self.include_uncategorized {
                uncategorized.insert(value, count);
            }
        }

        // Convert to CategorizedString with counts
        let categorized = categorized
            .into_iter()
            .map(|(cat, strings)| {
                let mut items: Vec<CategorizedString> = strings
                    .into_iter()
                    .map(|(value, count)| CategorizedString {
                        value,
                        category: cat,
                        count,
                    })
                    .collect();
                // Sort by count descending, then alphabetically
                items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
                (cat, items)
            })
            .collect();

        let mut uncategorized: Vec<String> = uncategorized.into_keys().collect();
        uncategorized.sort();

        AnalysisResult {
            file_name,
            file_size,
            categorized,
            uncategorized,
            total_strings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractor::Encoding;

    fn make_string(value: &str) -> ExtractedString {
        ExtractedString {
            value: value.to_string(),
            offset: 0,
            encoding: Encoding::Ascii,
        }
    }

    #[test]
    fn test_analyzer() {
        let analyzer = Analyzer::new(None, true);

        let strings = vec![
            make_string("https://example.com"),
            make_string("https://example.com"), // Duplicate
            make_string("/usr/local/bin"),
            make_string("test@example.com"),
            make_string("random string"),
        ];

        let result = analyzer.analyze(strings, Some("test.bin".to_string()), 1024);

        assert_eq!(result.total_strings, 5);
        assert_eq!(result.categorized.get(&Category::Url).unwrap().len(), 1);
        assert_eq!(
            result.categorized.get(&Category::Url).unwrap()[0].count,
            2
        );
        assert_eq!(result.categorized.get(&Category::Path).unwrap().len(), 1);
        assert_eq!(result.categorized.get(&Category::Email).unwrap().len(), 1);
        assert_eq!(result.uncategorized.len(), 1);
    }
}
