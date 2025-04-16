#!/usr/bin/env python3
"""
HeapHunter - Java Memory Dump Analyzer (Optimized Version)

A tool for extracting sensitive information like passwords, tokens,
credentials, and cryptographic artifacts from heap dumps.

Author: Original by NDIx, Optimized version
"""

import argparse
import os
import sys
import time
from pathlib import Path

# Try to import psutil for memory monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[i] psutil not installed. Memory usage monitoring will be disabled.")
    print("    Install with: pip install psutil")

# Add modules directory to Python path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODULE_DIR = os.path.join(SCRIPT_DIR, 'modules')
sys.path.append(MODULE_DIR)

# Import optimized modules
from extractor import extract_strings, load_keys
from analyzer import OptimizedStringAnalyzer
from reporter import ReportGenerator


class OptimizedHeapHunter:
    """Main class for the optimized HeapHunter tool."""
    
    CONFIG_KEY_PATH = "keys.txt"
    
    def __init__(self, hprof_path: str, report_dir: str = "report", 
                 extraction_method: str = "auto", parallel: bool = True):
        """Initialize the HeapHunter with target file path and output directory.
        
        Args:
            hprof_path: Path to the heap dump file
            report_dir: Directory to save reports to
            extraction_method: Method to use for string extraction: "auto", "buffered", "mmap", or "parallel"
            parallel: Whether to use parallel processing for analysis
        """
        self.hprof_path = hprof_path
        self.report_dir = report_dir
        self.extraction_method = extraction_method
        self.parallel = parallel
        self.strings = []
        self.findings = []
        self.keys = []
        
        # Create report directory if it doesn't exist
        Path(report_dir).mkdir(exist_ok=True)
    
    def run(self, mode: str = "all") -> None:
        """Run the heap dump analysis with the specified mode.
        
        Args:
            mode: Analysis mode, one of: "all", "extract-only", "html-only",
                  "jwt-only", "sha256-only", "sha1-md5-only", "bcrypt-only", 
                  "decrypted-only"
        """
        start_time = time.time()
        print(f"[🦅] Scanning: {self.hprof_path}")
        
        # Monitor memory usage if psutil is available
        if PSUTIL_AVAILABLE:
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # 1. Extract strings from heap dump
        extract_start = time.time()
        self.strings = extract_strings(self.hprof_path, method=self.extraction_method)
        extract_time = time.time() - extract_start
        
        print(f"[+] Extraction completed in {extract_time:.2f} seconds")
        print(f"[+] Extracted {len(self.strings)} strings")
        
        if PSUTIL_AVAILABLE:
            strings_memory = process.memory_info().rss / 1024 / 1024 - initial_memory
            print(f"[+] Memory usage after extraction: {strings_memory:.2f} MB")
        
        # 2. Load decryption keys
        self.keys = load_keys(self.CONFIG_KEY_PATH)
        print(f"[+] Loaded {len(self.keys)} keys from config.")
        
        # 3. Analyze strings to find sensitive data
        analyze_start = time.time()
        analyzer = OptimizedStringAnalyzer(self.strings, self.keys)
        self.findings = analyzer.analyze_all()
        analyze_time = time.time() - analyze_start
        
        print(f"[+] Analysis completed in {analyze_time:.2f} seconds")
        print(f"[+] Found {len(self.findings)} potential secrets")
        
        if PSUTIL_AVAILABLE:
            analysis_memory = process.memory_info().rss / 1024 / 1024 - strings_memory - initial_memory
            print(f"[+] Memory usage for analysis: {analysis_memory:.2f} MB")
        
        # 4. Generate reports based on the specified mode
        report_start = time.time()
        reporter = ReportGenerator(self.findings, self.report_dir)
        
        if mode == "extract-only":
            reporter.export_token_lists()
        
        elif mode == "html-only":
            reporter.generate_html_report()
        
        elif mode in ["jwt-only", "sha256-only", "sha1-md5-only", "bcrypt-only"]:
            target_type = {
                "jwt-only": "jwt",
                "sha256-only": "sha256",
                "sha1-md5-only": "sha1/md5",
                "bcrypt-only": "bcrypt"
            }[mode]
            
            grouped = analyzer.group_findings()
            filtered_findings = grouped.get(target_type, [])
            reporter.generate_html_report(filtered_findings)
        
        elif mode == "decrypted-only":
            decrypted_only = [f for f in self.findings if f.get("brute_decrypted")]
            reporter.generate_html_report(decrypted_only)
        
        else:  # Default: do everything
            reporter.generate_html_report()
            reporter.export_token_lists()
        
        report_time = time.time() - report_start
        total_time = time.time() - start_time
        
        print(f"[+] Report generation completed in {report_time:.2f} seconds")
        print(f"[+] Total execution time: {total_time:.2f} seconds")
        print(f"[+] Analysis complete. Reports saved to: {self.report_dir}")


def print_help() -> None:
    """Print usage information."""
    print("""
🦅 Heapdump Hunter Usage (Optimized Version):
--------------------------------------------

python heaphunter.py [heapdump.hprof] [options]

Options:
  --extract-only       Only export sha256 / jwt / bcrypt / md5 hashes to .txt
  --html-only          Only generate HTML reports (no .txt exports)
  --jwt-only           Only generate report for JWT tokens
  --sha256-only        Only generate report for SHA256 hashes
  --sha1-md5-only      Only generate report for SHA1/MD5 hashes
  --bcrypt-only        Only generate report for bcrypt hashes
  --decrypted-only     Only show AES-decrypted values
  --method METHOD      String extraction method: auto, buffered, mmap, parallel (default: auto)
  --sequential         Disable parallel processing (for debugging or low-memory systems)
  --help               Show this help and exit

Defaults:
  - All reports and exports are saved to the ./report/ folder
  - Output includes per-type HTML reports + index.html dashboard
  - Automatic extraction method is selected based on file size
  - Parallel processing is enabled by default

🔐 keys.txt – AES decryption keys:
-----------------------------------
Place your common AES decryption keys (for Base64 blobs) in a keys.txt file.
One key per line.

Example:
  secret123
  jwt-secret
  mypasswordkey
  springbootkey

These keys will be used to try decrypting Base64 strings found in the heapdump.

Examples:
  python heaphunter.py heapdump.hprof
  python heaphunter.py heapdump.hprof --extract-only
  python heaphunter.py heapdump.hprof --sha256-only --method mmap
  python heaphunter.py heapdump.hprof --sequential
""")


def main() -> None:
    """Main function to parse arguments and run the HeapHunter."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("heapdump", nargs="?", default="heapdump.hprof")
    parser.add_argument("--extract-only", action="store_true")
    parser.add_argument("--html-only", action="store_true")
    parser.add_argument("--jwt-only", action="store_true")
    parser.add_argument("--sha256-only", action="store_true")
    parser.add_argument("--sha1-md5-only", action="store_true")
    parser.add_argument("--bcrypt-only", action="store_true")
    parser.add_argument("--decrypted-only", action="store_true")
    parser.add_argument("--method", choices=["auto", "buffered", "mmap", "parallel"], default="auto")
    parser.add_argument("--sequential", action="store_true", help="Disable parallel processing")
    parser.add_argument("--help", action="store_true")
    args = parser.parse_args()
    
    if args.help:
        print_help()
        exit(0)
    
    # Validate that the heap dump file exists
    if not os.path.exists(args.heapdump):
        print(f"[!] Error: Heap dump file not found: {args.heapdump}")
        exit(1)
    
    # Create a unique report directory based on the input filename
    base_filename = os.path.splitext(os.path.basename(args.heapdump))[0]
    report_dir = f"report_{base_filename}"
    
    # Determine the mode of operation
    mode = "all"
    if args.extract_only:
        mode = "extract-only"
    elif args.html_only:
        mode = "html-only"
    elif args.jwt_only:
        mode = "jwt-only"
    elif args.sha256_only:
        mode = "sha256-only"
    elif args.sha1_md5_only:
        mode = "sha1-md5-only"
    elif args.bcrypt_only:
        mode = "bcrypt-only"
    elif args.decrypted_only:
        mode = "decrypted-only"
    
    # Initialize and run the heap hunter
    hunter = OptimizedHeapHunter(
        args.heapdump, 
        report_dir=report_dir,
        extraction_method=args.method,
        parallel=not args.sequential
    )
    hunter.run(mode=mode)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user")
        exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        exit(1)