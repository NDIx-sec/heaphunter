"""
HeapHunter - Optimized String Analysis

This module provides optimized functionality for analyzing strings from heap dumps
to find sensitive information like credentials, tokens, and other secrets.
Uses parallel processing and efficient algorithms.
"""

import re
import collections
from typing import Dict, List, Set, Tuple, Any, Optional, Generator, Iterator
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import multiprocessing as mp
import itertools
import functools

# Import utils module (assume it's been optimized too)
from utils import (
    SENSITIVE_PATTERNS, is_probable_key, is_likely_key_name, is_real_value,
    is_strong_candidate, is_plausible_credential, try_decode_base64,
    try_parse_json, try_decrypt_base64_ciphertext
)

# Define a named tuple for more memory-efficient storage
Credential = collections.namedtuple(
    'Credential', 
    ['type', 'line', 'match', 'source_key', 'line_number', 'base64_decoded', 
     'json_parsed', 'brute_decrypted']
)

# Make fields optional with defaults
Credential.__new__.__defaults__ = (None,) * len(Credential._fields)


class OptimizedStringAnalyzer:
    """Analyzes strings to find sensitive information using optimized methods."""
    
    def __init__(self, strings: List[str], keys: List[str], 
                 max_workers: int = None, chunk_size: int = 10000):
        """Initialize the analyzer with extracted strings and decryption keys.
        
        Args:
            strings: List of strings to analyze
            keys: List of potential decryption keys
            max_workers: Maximum number of worker processes to use (default: CPU count)
            chunk_size: Size of string chunks for parallel processing
        """
        self.strings = strings
        self.keys = keys
        self.findings = []
        self.max_workers = max_workers or mp.cpu_count()
        self.chunk_size = chunk_size
        
        # Create an index of interesting keywords for faster lookup
        self.keyword_index = self._build_keyword_index()
    
    def _build_keyword_index(self) -> Dict[str, List[int]]:
        """Build an index of interesting keywords for faster lookup.
        
        Returns:
            Dictionary mapping keywords to lists of line indices
        """
        print("[+] Building keyword index...")
        index = collections.defaultdict(list)
        
        # Keywords to index
        interesting_keywords = [
            "password", "passwd", "pwd", "pass", "secret", "token", "key",
            "credential", "auth", "security", "jwt", "private", "apikey",
            "access", "jwt_secret", "secret_key", "encryption", "crypto",
            "user", "username", "login", "bearer", "apikey"
        ]
        
        # Build the index
        for idx, line in enumerate(self.strings):
            line_lower = line.lower()
            for keyword in interesting_keywords:
                if keyword in line_lower:
                    index[keyword].append(idx)
        
        print(f"[+] Indexed {sum(len(v) for v in index.values())} keyword occurrences")
        return index
    
    def analyze_all(self) -> List[Dict]:
        """Run all analysis methods to find sensitive data in parallel.
        
        Returns:
            List of findings
        """
        print("[+] Starting parallel analysis of all data...")
        
        # Split analysis into independent tasks that can run in parallel
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit pattern hunting jobs in parallel
            pattern_futures = []
            
            # Split strings into chunks for parallel processing
            chunks = [self.strings[i:i+self.chunk_size] 
                      for i in range(0, len(self.strings), self.chunk_size)]
            
            for i, chunk in enumerate(chunks):
                for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                    pattern_futures.append(
                        executor.submit(
                            self._hunt_pattern_chunk, 
                            chunk, i * self.chunk_size, pattern_name, pattern, self.keys
                        )
                    )
            
            # Collect pattern results
            for future in as_completed(pattern_futures):
                self.findings.extend(future.result())
            
            print(f"[+] Found {len(self.findings)} pattern matches")
            
            # Run other analysis tasks in parallel
            analysis_futures = [
                executor.submit(self.hunt_contextual_passwords, self.strings, self.keys),
                executor.submit(self.hunt_key_value_sequences, self.strings),
                executor.submit(self.hunt_adjacent_credentials, self.strings),
                executor.submit(self.find_username_password_pairs, self.strings),
            ]
            
            # Collect other analysis results
            for future in as_completed(analysis_futures):
                self.findings.extend(future.result())
        
        # Filter fallback findings if stronger evidence exists (must be done serially)
        strong_keys = set(f['source_key'] for f in self.findings if f['type'] == 'credentials')
        self.findings = [
            f for f in self.findings
            if not (f['type'] == 'fallback_credential' and f['source_key'] in strong_keys)
        ]
        
        # Filter credential findings
        before = len([f for f in self.findings if f['type'] == 'credentials'])
        credentials_raw = [f for f in self.findings if f['type'] == 'credentials']
        credentials_filtered = self.filter_credential_findings(credentials_raw)
        non_credentials = [f for f in self.findings if f['type'] != 'credentials']
        self.findings = non_credentials + credentials_filtered
        after = len([f for f in self.findings if f['type'] == 'credentials'])
        print(f"🔍 Filtered credentials: {before} → {after}")
        
        return self.findings
    
    @staticmethod
    def _hunt_pattern_chunk(chunk: List[str], offset: int, pattern_name: str, 
                           pattern: re.Pattern, keylist: List[str]) -> List[Dict]:
        """Search for a specific pattern in a chunk of strings.
        
        Args:
            chunk: List of strings to search
            offset: Line number offset for this chunk
            pattern_name: Name of the pattern being searched
            pattern: Compiled regex pattern to search for
            keylist: List of decryption keys to try
            
        Returns:
            List of findings for this pattern in this chunk
        """
        findings = []
        for idx, line in enumerate(chunk):
            line_number = offset + idx + 1
            matches = pattern.findall(line)
            for match in matches:
                data = match[-1] if isinstance(match, tuple) else match
                base64_decoded = try_decode_base64(data)
                json_parsed = try_parse_json(base64_decoded) if base64_decoded else None
                brute_results = []
                if pattern_name == "base64":
                    brute_results = try_decrypt_base64_ciphertext(data, keylist)
                
                findings.append({
                    'type': pattern_name,
                    'line': line.strip(),
                    'match': data,
                    'base64_decoded': base64_decoded,
                    'json_parsed': json_parsed,
                    'brute_decrypted': brute_results,
                    'line_number': line_number
                })
        return findings
    
    def hunt_contextual_passwords(self, strings: List[str], keylist: List[str], lookahead: int = 3) -> List[Dict]:
        """Find password-like values near password-related keywords using the keyword index.
        
        Args:
            strings: List of strings to search
            keylist: List of decryption keys
            lookahead: Number of lines to look ahead for values
            
        Returns:
            List of findings
        """
        print("[+] Hunting for contextual passwords...")
        findings = []
        
        # Keywords to look for
        password_keywords = [
            "password", "passwd", "pwd", "pass", "secret", "token", "key",
            "credential", "auth", "security", "jwt", "private", "apikey",
            "access", "jwt_secret", "secret_key", "encryption", "crypto"
        ]
        
        # Only search lines containing our keywords (use the index)
        candidate_indices = set()
        for keyword in password_keywords:
            if keyword in self.keyword_index:
                candidate_indices.update(self.keyword_index[keyword])
        
        for idx in sorted(candidate_indices):
            line = strings[idx]
            
            for offset in range(1, lookahead + 1):
                if idx + offset >= len(strings):
                    continue
                
                candidate = strings[idx + offset].strip()
                candidate = re.sub(r'[^a-zA-Z0-9+/=]+$', '', candidate)
                
                if is_probable_key(candidate) or is_likely_key_name(candidate):
                    continue
                
                if (
                    len(candidate) >= 8
                    and all(c.isprintable() for c in candidate)
                    and not any(c.isspace() for c in candidate)
                    and (is_strong_candidate(candidate) or candidate.endswith('=') or try_decode_base64(candidate))
                ):
                    findings.append({
                        'type': 'fallback_credential',
                        'line': line.strip(),
                        'source_key': line.strip(),
                        'match': candidate.strip().strip('#!;:'),
                        'line_number': idx + offset + 1,
                        'base64_decoded': try_decode_base64(candidate),
                        'json_parsed': try_parse_json(candidate),
                        'brute_decrypted': try_decrypt_base64_ciphertext(candidate, keylist)
                    })
                    break  # Only take the first value if it's not a key
        
        print(f"[+] Found {len(findings)} contextual passwords")
        return findings
    
    def hunt_key_value_sequences(self, strings: List[str]) -> List[Dict]:
        """Find key-value pairs in consecutive strings using optimized searching.
        
        Args:
            strings: List of strings to search
            
        Returns:
            List of findings
        """
        print("[+] Hunting for key-value sequences...")
        findings = []
        
        # Process in chunks for better memory management
        chunk_size = 10000
        chunks = [strings[i:i+chunk_size] for i in range(0, len(strings), chunk_size)]
        
        for chunk_idx, chunk in enumerate(chunks):
            offset = chunk_idx * chunk_size
            
            for idx in range(len(chunk) - 1):
                key = chunk[idx].strip()
                val = chunk[idx + 1].strip()
                
                if not is_probable_key(key):
                    continue
                if not val or len(val) < 6:
                    continue
                if not all(c.isprintable() and not c.isspace() for c in val):
                    continue
                
                findings.append({
                    'type': 'credentials',
                    'source_key': key,
                    'line': key,
                    'match': val.strip().strip('#!;:'),
                    'line_number': offset + idx + 2,
                    'base64_decoded': try_decode_base64(val),
                    'json_parsed': try_parse_json(val),
                    'brute_decrypted': try_decrypt_base64_ciphertext(val, self.keys)
                })
        
        print(f"[+] Found {len(findings)} key-value sequences")
        return findings
    
    def hunt_adjacent_credentials(self, strings: List[str]) -> List[Dict]:
        """Find potential credential pairs in adjacent strings.
        
        Args:
            strings: List of strings to search
            
        Returns:
            List of findings
        """
        print("[+] Hunting for adjacent credentials...")
        findings = []
        
        # Process in chunks for better memory management
        chunk_size = 10000
        chunks = [strings[i:i+chunk_size] for i in range(0, len(strings), chunk_size)]
        
        for chunk_idx, chunk in enumerate(chunks):
            offset = chunk_idx * chunk_size
            
            for i in range(len(chunk) - 2):
                maybe_key = chunk[i + 1].strip()
                maybe_val = chunk[i + 2].strip()
                
                if not is_probable_key(maybe_key):
                    continue
                if not maybe_val or len(maybe_val) < 6:
                    continue
                if not all(c.isprintable() and not c.isspace() for c in maybe_val):
                    continue
                
                findings.append({
                    'type': 'credentials',
                    'source_key': maybe_key,
                    'line': maybe_key,
                    'match': maybe_val.strip().strip('#!;:'),
                    'line_number': offset + i + 3,
                    'base64_decoded': try_decode_base64(maybe_val),
                    'json_parsed': try_parse_json(maybe_val),
                    'brute_decrypted': try_decrypt_base64_ciphertext(maybe_val, self.keys)
                })
        
        print(f"[+] Found {len(findings)} adjacent credentials")
        return findings
    
    def find_username_password_pairs(self, strings: List[str]) -> List[Dict]:
        """Find username and password pairs that share a common prefix.
        
        Args:
            strings: List of strings to search
            
        Returns:
            List of findings
        """
        print("[+] Finding username-password pairs...")
        user_keywords = ['user', 'username', 'login']
        pass_keywords = ['password', 'passwd', 'pwd', 'secret']
        
        user_entries = {}
        pass_entries = {}
        
        # Get candidate indices from the keyword index
        candidate_indices = set()
        for keyword in user_keywords + pass_keywords:
            if keyword in self.keyword_index:
                candidate_indices.update(self.keyword_index[keyword])
        
        # Process only lines with relevant keywords
        for idx in sorted(candidate_indices):
            if idx + 1 >= len(strings):
                continue
                
            k = strings[idx].strip()
            v = strings[idx + 1].strip()
            
            if not is_probable_key(k):
                continue
            if is_probable_key(v):
                continue
            if not is_real_value(v):
                continue
            
            k_lc = k.lower()
            
            for kw in user_keywords:
                if kw in k_lc:
                    prefix = k.rsplit('.', 1)[0] if '.' in k else None
                    if prefix:
                        user_entries.setdefault(prefix, []).append({
                            "key": k,
                            "value": v
                        })
            
            for kw in pass_keywords:
                if kw in k_lc:
                    prefix = k.rsplit('.', 1)[0] if '.' in k else None
                    if prefix:
                        pass_entries.setdefault(prefix, []).append({
                            "key": k,
                            "value": v
                        })
        
        pairs = []
        for prefix in user_entries:
            if prefix in pass_entries:
                for user in user_entries[prefix]:
                    for pw in pass_entries[prefix]:
                        if user['value'] == pw['value']:
                            continue
                        if not is_plausible_credential(user['key'], user['value']):
                            continue
                        if not is_plausible_credential(pw['key'], pw['value']):
                            continue
                        
                        pairs.append({
                            'type': 'credential_pair',
                            'prefix': prefix,
                            'username_key': user['key'],
                            'username_val': user['value'],
                            'password_key': pw['key'],
                            'password_val': pw['value']
                        })
        
        print(f"[+] Found {len(pairs)} username-password pairs")
        return pairs
    
    def filter_credential_findings(self, findings: List[Dict]) -> List[Dict]:
        """Filter credential findings to reduce false positives.
        
        Args:
            findings: List of credential findings
            
        Returns:
            Filtered list of findings
        """
        valid = []
        
        for f in findings:
            if f['type'] != 'credentials':
                continue
            
            pwd = f.get('match') or f.get('password') or ''
            pwd_str = str(pwd).strip().strip('#!;:=')
            key = f.get('source_key', '') or f.get('line', '')
            key_lc = key.lower()
            
            # If key is trusted, accept if password is at least 8 chars
            if any(kw in key_lc for kw in ['password', 'secret', 'token', 'key', 'jwt', 'username', 'user']):
                if len(pwd_str) >= 8:
                    valid.append(f)
                    continue
            
            # If base64-like or strong character-wise
            if len(pwd_str) >= 20 and re.match(r'^[A-Za-z0-9+/=]+$', pwd_str):
                valid.append(f)
                continue
            
            # If strong password candidate
            if is_strong_candidate(pwd_str):
                valid.append(f)
                continue
        
        return valid
    
    def group_findings(self) -> Dict[str, List[Dict]]:
        """Group findings by type.
        
        Returns:
            Dictionary mapping types to lists of findings
        """
        grouped = {}
        for f in self.findings:
            grouped.setdefault(f['type'], []).append(f)
        return grouped
