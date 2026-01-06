use std::collections::HashSet;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
    Latin1,
}

impl Encoding {
    pub fn all() -> Vec<Encoding> {
        vec![
            Encoding::Ascii,
            Encoding::Utf8,
            Encoding::Utf16Le,
            Encoding::Utf16Be,
            Encoding::Utf32Le,
            Encoding::Utf32Be,
            Encoding::Latin1,
        ]
    }

    pub fn default_set() -> Vec<Encoding> {
        vec![Encoding::Ascii, Encoding::Utf16Le]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Encoding::Ascii => "ascii",
            Encoding::Utf8 => "utf8",
            Encoding::Utf16Le => "utf16le",
            Encoding::Utf16Be => "utf16be",
            Encoding::Utf32Le => "utf32le",
            Encoding::Utf32Be => "utf32be",
            Encoding::Latin1 => "latin1",
        }
    }

    pub fn from_name(name: &str) -> Option<Encoding> {
        match name.to_lowercase().as_str() {
            "ascii" => Some(Encoding::Ascii),
            "utf8" | "utf-8" => Some(Encoding::Utf8),
            "utf16le" | "utf16-le" | "utf-16le" | "utf-16-le" => Some(Encoding::Utf16Le),
            "utf16be" | "utf16-be" | "utf-16be" | "utf-16-be" => Some(Encoding::Utf16Be),
            "utf16" => Some(Encoding::Utf16Le), // Default to LE
            "utf32le" | "utf32-le" | "utf-32le" | "utf-32-le" => Some(Encoding::Utf32Le),
            "utf32be" | "utf32-be" | "utf-32be" | "utf-32-be" => Some(Encoding::Utf32Be),
            "utf32" => Some(Encoding::Utf32Le), // Default to LE
            "latin1" | "iso-8859-1" | "iso88591" => Some(Encoding::Latin1),
            "all" => None, // Special case handled elsewhere
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub encoding: Encoding,
}

pub struct StringExtractor {
    min_length: usize,
    encodings: Vec<Encoding>,
}

impl StringExtractor {
    pub fn new(min_length: usize, encodings: Vec<Encoding>) -> Self {
        Self {
            min_length,
            encodings,
        }
    }

    pub fn extract(&self, data: &[u8]) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for encoding in &self.encodings {
            let strings = match encoding {
                Encoding::Ascii => self.extract_ascii(data),
                Encoding::Utf8 => self.extract_utf8(data),
                Encoding::Utf16Le => self.extract_utf16(data, true),
                Encoding::Utf16Be => self.extract_utf16(data, false),
                Encoding::Utf32Le => self.extract_utf32(data, true),
                Encoding::Utf32Be => self.extract_utf32(data, false),
                Encoding::Latin1 => self.extract_latin1(data),
            };

            for s in strings {
                if !seen.contains(&s.value) {
                    seen.insert(s.value.clone());
                    results.push(s);
                }
            }
        }

        results
    }

    pub fn extract_from_reader<R: Read>(&self, reader: &mut R) -> std::io::Result<Vec<ExtractedString>> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(self.extract(&data))
    }

    fn extract_ascii(&self, data: &[u8]) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let mut current = String::new();
        let mut start_offset = 0;

        for (i, &byte) in data.iter().enumerate() {
            if is_printable_ascii(byte) {
                if current.is_empty() {
                    start_offset = i;
                }
                current.push(byte as char);
            } else {
                if current.len() >= self.min_length {
                    results.push(ExtractedString {
                        value: current.clone(),
                        offset: start_offset,
                        encoding: Encoding::Ascii,
                    });
                }
                current.clear();
            }
        }

        if current.len() >= self.min_length {
            results.push(ExtractedString {
                value: current,
                offset: start_offset,
                encoding: Encoding::Ascii,
            });
        }

        results
    }

    fn extract_utf8(&self, data: &[u8]) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let mut i = 0;

        while i < data.len() {
            // Find start of valid UTF-8 sequence
            let start = i;
            let mut current = String::new();

            while i < data.len() {
                // Try to decode UTF-8 character
                let remaining = &data[i..];
                if let Some((ch, len)) = decode_utf8_char(remaining) {
                    if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
                        break;
                    }
                    // Only include if it's a multi-byte char or printable ASCII
                    if len > 1 || is_printable_ascii(data[i]) {
                        current.push(ch);
                        i += len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            // Only keep strings with actual UTF-8 content (multi-byte chars)
            if current.len() >= self.min_length && current.chars().any(|c| c.len_utf8() > 1) {
                results.push(ExtractedString {
                    value: current,
                    offset: start,
                    encoding: Encoding::Utf8,
                });
            }

            i += 1;
        }

        results
    }

    fn extract_utf16(&self, data: &[u8], little_endian: bool) -> Vec<ExtractedString> {
        let mut results = Vec::new();

        if data.len() < 2 {
            return results;
        }

        let mut i = 0;
        while i + 1 < data.len() {
            let start = i;
            let mut current = String::new();

            while i + 1 < data.len() {
                let code_unit = if little_endian {
                    u16::from_le_bytes([data[i], data[i + 1]])
                } else {
                    u16::from_be_bytes([data[i], data[i + 1]])
                };

                // Handle surrogate pairs
                if (0xD800..=0xDBFF).contains(&code_unit) {
                    // High surrogate - need low surrogate
                    if i + 3 < data.len() {
                        let low = if little_endian {
                            u16::from_le_bytes([data[i + 2], data[i + 3]])
                        } else {
                            u16::from_be_bytes([data[i + 2], data[i + 3]])
                        };

                        if (0xDC00..=0xDFFF).contains(&low) {
                            let code_point = 0x10000
                                + ((code_unit as u32 - 0xD800) << 10)
                                + (low as u32 - 0xDC00);
                            if let Some(ch) = char::from_u32(code_point) {
                                current.push(ch);
                                i += 4;
                                continue;
                            }
                        }
                    }
                    break;
                } else if (0xDC00..=0xDFFF).contains(&code_unit) {
                    // Orphan low surrogate
                    break;
                } else if let Some(ch) = char::from_u32(code_unit as u32) {
                    if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
                        break;
                    }
                    if ch == '\0' {
                        break;
                    }
                    current.push(ch);
                    i += 2;
                } else {
                    break;
                }
            }

            if current.len() >= self.min_length {
                results.push(ExtractedString {
                    value: current,
                    offset: start,
                    encoding: if little_endian {
                        Encoding::Utf16Le
                    } else {
                        Encoding::Utf16Be
                    },
                });
            }

            i += 2;
        }

        results
    }

    fn extract_utf32(&self, data: &[u8], little_endian: bool) -> Vec<ExtractedString> {
        let mut results = Vec::new();

        if data.len() < 4 {
            return results;
        }

        let mut i = 0;
        while i + 3 < data.len() {
            let start = i;
            let mut current = String::new();

            while i + 3 < data.len() {
                let code_point = if little_endian {
                    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
                } else {
                    u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
                };

                if let Some(ch) = char::from_u32(code_point) {
                    if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
                        break;
                    }
                    if ch == '\0' {
                        break;
                    }
                    current.push(ch);
                    i += 4;
                } else {
                    break;
                }
            }

            if current.len() >= self.min_length {
                results.push(ExtractedString {
                    value: current,
                    offset: start,
                    encoding: if little_endian {
                        Encoding::Utf32Le
                    } else {
                        Encoding::Utf32Be
                    },
                });
            }

            i += 4;
        }

        results
    }

    fn extract_latin1(&self, data: &[u8]) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let mut current = String::new();
        let mut start_offset = 0;
        let mut has_extended = false;

        for (i, &byte) in data.iter().enumerate() {
            // Latin-1 printable: 0x20-0x7E (ASCII) and 0xA0-0xFF (extended)
            if is_printable_ascii(byte) || (0xA0..=0xFF).contains(&byte) {
                if current.is_empty() {
                    start_offset = i;
                }
                current.push(byte as char);
                if byte >= 0xA0 {
                    has_extended = true;
                }
            } else {
                // Only include if it has extended Latin-1 chars (otherwise it's just ASCII)
                if current.len() >= self.min_length && has_extended {
                    results.push(ExtractedString {
                        value: current.clone(),
                        offset: start_offset,
                        encoding: Encoding::Latin1,
                    });
                }
                current.clear();
                has_extended = false;
            }
        }

        if current.len() >= self.min_length && has_extended {
            results.push(ExtractedString {
                value: current,
                offset: start_offset,
                encoding: Encoding::Latin1,
            });
        }

        results
    }
}

fn is_printable_ascii(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r'
}

fn decode_utf8_char(data: &[u8]) -> Option<(char, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];

    // Single byte (ASCII)
    if first < 0x80 {
        return Some((first as char, 1));
    }

    // Multi-byte sequence
    let (len, min_code_point) = if first & 0xE0 == 0xC0 {
        (2, 0x80)
    } else if first & 0xF0 == 0xE0 {
        (3, 0x800)
    } else if first & 0xF8 == 0xF0 {
        (4, 0x10000)
    } else {
        return None;
    };

    if data.len() < len {
        return None;
    }

    // Verify continuation bytes
    for i in 1..len {
        if data[i] & 0xC0 != 0x80 {
            return None;
        }
    }

    // Decode
    let code_point = match len {
        2 => ((first & 0x1F) as u32) << 6 | (data[1] & 0x3F) as u32,
        3 => {
            ((first & 0x0F) as u32) << 12
                | ((data[1] & 0x3F) as u32) << 6
                | (data[2] & 0x3F) as u32
        }
        4 => {
            ((first & 0x07) as u32) << 18
                | ((data[1] & 0x3F) as u32) << 12
                | ((data[2] & 0x3F) as u32) << 6
                | (data[3] & 0x3F) as u32
        }
        _ => return None,
    };

    // Check for overlong encoding
    if code_point < min_code_point {
        return None;
    }

    char::from_u32(code_point).map(|c| (c, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii() {
        let extractor = StringExtractor::new(4, vec![Encoding::Ascii]);
        let data = b"hello\x00world\x00ab\x00test";
        let strings = extractor.extract(data);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].value, "hello");
        assert_eq!(strings[1].value, "world");
        assert_eq!(strings[2].value, "test");
    }

    #[test]
    fn test_extract_utf16le() {
        let extractor = StringExtractor::new(4, vec![Encoding::Utf16Le]);
        // "hello" in UTF-16LE
        let data = b"h\x00e\x00l\x00l\x00o\x00\x00\x00";
        let strings = extractor.extract(data);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello");
    }
}
