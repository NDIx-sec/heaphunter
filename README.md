# HeapHunter

## Overview

HeapHunter is a powerful Python-based tool designed to analyze Java heap dump files to discover sensitive information (passwords, tokens, secret keys, JWTs, etc.). The application can process large heap dumps and identify potentially sensitive data, then create user-friendly HTML and text reports of the findings.

## Key Features

- Detection of various types of sensitive information (passwords, tokens, JWT, hash values)
- Automatic decoding of different data formats (Base64, JWT)
- AES decryption attempts for encrypted data using a provided key list
- Parallel data processing for performance optimization
- Memory-efficient processing techniques for handling large heap dumps
- Advanced filtering techniques to minimize false positives
- Interactive HTML reports with detailed information

## Installation

### Prerequisites

- Python 3.6 or newer
- PyCryptodome library (for AES decoding) - optional
- psutil library (for memory usage monitoring) - optional

### Installation Steps

1. Clone the project:
```bash
git clone https://github.com/yourusername/heaphunter.git
cd heaphunter
```

2. Install dependencies:
```bash
pip install pycryptodome psutil
```

## Usage

### Basic Usage

```bash
python main.py heapdump.hprof
```

This analyzes the heap dump and creates all types of reports.

### Switches and Options

```bash
python main.py [heapdump.hprof] [options]
```

Options:
- `--extract-only`: Only export sha256 / jwt / bcrypt / md5 hashes to .txt files
- `--html-only`: Only generate HTML reports (no .txt exports)
- `--jwt-only`: Only generate report for JWT tokens
- `--sha256-only`: Only generate report for SHA256 hashes
- `--sha1-md5-only`: Only generate report for SHA1/MD5 hashes
- `--bcrypt-only`: Only generate report for bcrypt hashes
- `--decrypted-only`: Only show AES-decrypted values
- `--method METHOD`: String extraction method: auto, buffered, mmap, parallel (default: auto)
- `--sequential`: Disable parallel processing (for debugging or low-memory systems)
- `--help`: Show help and exit

### Optimized Version

For even more efficient operation, use the optimized version:

```bash
python optimized_main.py heapdump.hprof
```

The optimized version automatically selects the most efficient processing method based on file size and system capabilities.

### AES Decoding

To attempt decryption of AES-encrypted data, create a `keys.txt` file in the following format:

```
secret123
jwt-secret
mypasswordkey
springbootkey
```

## Module Description

The project has a modular structure which improves code readability and maintainability:

### main.py / optimized_main.py
- Entry point of the program
- Processes command line arguments
- Initializes and runs the HeapHunter / OptimizedHeapHunter class

### extractor.py / optimized_extractor.py
- Extracts strings from the heap dump
- The optimized version supports buffered, mmap, and parallel reading modes
- Reads configuration (AES keys from the `keys.txt` file)

### analyzer.py / optimized_analyzer.py
- Analyzes the extracted strings to identify various sensitive information
- Applies different search strategies (pattern matching, contextual search, key-value pairs)
- The optimized version uses parallel processing and context-aware indexing

### reporter.py
- Generates HTML reports and text extracts of the findings
- Creates an interactive dashboard to overview the findings
- Formats and organizes findings by type

### utils.py / improved_utils.py
- Basic utility functions (Base64 decoding, JWT decoding, AES decryption)
- Regular expressions and filters for recognizing different sensitive information
- Advanced filtering techniques to reduce false positives

## Advanced Filtering Techniques

HeapHunter applies advanced filtering methods to minimize false positives, with special attention to Java-specific artifacts. The `improved_utils.py` module contains these techniques:

- Recognition and filtering of Java type patterns (e.g., "Lorg/hibernate", "java.util")
- Credential format validation (character set, length, complexity)
- Context-based filtering to identify real passwords and tokens

## Reports

After analysis, the program generates several reports in the `report_[heapdump_name]` folder:

- `index.html` - Dashboard to overview all reports
- Type-specific reports (jwt, sha256, credentials, etc.)
- Decoded data report
- Text extracts of hashes and tokens

## Examples

### Default analysis:
```bash
python main.py heapdump.hprof
```

### Analyze only JWT tokens with memory-mapped method:
```bash
python optimized_main.py heapdump.hprof --jwt-only --method mmap
```

### Extract only hashes to text files:
```bash
python main.py heapdump.hprof --extract-only
```

## Performance Optimization

- For large heap dumps (>100MB), it is recommended to use `--method mmap` or `--method parallel`
- On systems with very limited memory, use the `--method buffered --sequential` combination
- The optimized version automatically adapts to the file size and available resources

## Troubleshooting

- **"Error: Heap dump file not found"**: Check the file path
- **"PyCryptodome not installed"**: Install the pycryptodome package for AES decoding
- **"Memory mapping failed"**: The system does not support memory mapping, try the `--method buffered` option

## License

[MIT License]

## Author

Original author: NDIx
Optimized version: [Your name]
