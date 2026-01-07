# sift

Intelligent binary string extraction and analysis. Like `strings`, but smarter.

## Features

- **Smart categorization** - Automatically detects and groups:
  - URLs, paths, UUIDs, emails
  - IPv4/IPv6 addresses
  - Versions, dates, hashes
  - **Secrets** (API keys, tokens, private keys - GitHub, AWS, Slack, Stripe, JWTs, high-entropy strings)
  - Debug/error messages (format strings, error keywords)
  - Identifiers (function names, variables)
  - Config values (key=value patterns)
  - Commands (AT commands, etc.)
  - Other interesting strings (firmware-related terms)

- **Multiple encodings** - ASCII, UTF-8, UTF-16 (LE/BE), UTF-32, Latin-1

- **Flexible output** - Human-readable, JSON, summary, or raw

- **Filters out noise** - Excludes mangled symbols, hash-like garbage

## Installation

```bash
cargo install --path .
```

## Usage

```bash
# Analyze a binary
sift /path/to/binary

# Analyze with piped input
cat firmware.bin | sift

# Scan current directory
sift

# Recursive directory scan
sift -r /path/to/dir

# Filter by category
sift -t url,path,ident binary.exe

# JSON output
sift -o json firmware.bin

# Show all strings including uncategorized
sift -v binary
```

## Options

```
-n, --min-length <LENGTH>   Minimum string length [default: 4]
-e, --encoding <ENCODINGS>  Encodings: ascii, utf8, utf16, utf16le, utf16be, utf32, latin1, all
-t, --type <TYPES>          Filter: url, path, uuid, email, ipv4, ipv6, version, date, hash,
                            secret, debug, ident, config, cmd, interesting
-o, --output <FORMAT>       Output: human, json, summary, raw [default: human]
-r, --recursive             Scan directories recursively
-v, --verbose               Show all strings, including uncategorized
    --max-items <COUNT>     Max items per category [default: 20, 0 = unlimited]
    --no-color              Suppress colorized output
```

## Example Output

```
firmware.bin (2.1 MB)

 URLs (3)
   https://api.example.com/v1/update
   http://192.168.1.1/config
   ftp://files.internal/firmware

 Paths (12)
   /etc/config/settings.json
   /usr/bin/update_handler
   /var/log/system.log
   ...

 Secrets (2)
   ghp_1234567890abcdefghijABCDEFGHIJKLMNOP
   AKIAIOSFODNN7EXAMPLE

 Debug/Errors (28)
   %s: failed to open %s
   Error: connection refused
   Warning: buffer overflow detected
   ...

 Identifiers (45)
   initPeripheralController
   uart_send_byte
   FIRMWARE_VERSION
   ...

────────────────────────────────────────
  Total: 1,234  Categorized: 158 (12.8%)
```

## License

MIT
