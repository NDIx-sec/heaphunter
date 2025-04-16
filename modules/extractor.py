"""
HeapHunter - Optimized String Extractor

This module provides optimized functionality for extracting strings from binary files,
particularly Java heap dumps, using buffered reading and parallel processing.
"""

import os
import mmap
import io
from typing import List, Iterator, Generator
from pathlib import Path
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed


def extract_strings_buffered(filepath: str, min_length: int = 4, 
                             buffer_size: int = 1024 * 1024) -> Generator[str, None, None]:
    """Extract printable ASCII strings from a binary file using buffered reading.
    
    Args:
        filepath: Path to the binary file
        min_length: Minimum length of strings to extract
        buffer_size: Size of buffer for reading file chunks
        
    Yields:
        Extracted strings one by one
    """
    print(f"[+] Extracting strings from {filepath} using buffered reading...")
    
    current = bytearray()
    file_size = os.path.getsize(filepath)
    processed = 0
    
    with open(filepath, 'rb') as f:
        while True:
            buffer = f.read(buffer_size)
            if not buffer:
                break
                
            processed += len(buffer)
            if processed % (100 * buffer_size) == 0:
                print(f"[+] Processing: {processed / file_size:.1%} complete")
            
            for byte in buffer:
                if 32 <= byte <= 126:  # Printable ASCII
                    current.append(byte)
                else:
                    if len(current) >= min_length:
                        yield current.decode('ascii', errors='ignore')
                    current = bytearray()
    
    # Don't forget the last string if it ends at EOF
    if len(current) >= min_length:
        yield current.decode('ascii', errors='ignore')


def extract_strings_mmap(filepath: str, min_length: int = 4) -> Generator[str, None, None]:
    """Extract printable ASCII strings from a binary file using memory mapping.
    
    Args:
        filepath: Path to the binary file
        min_length: Minimum length of strings to extract
        
    Yields:
        Extracted strings one by one
    """
    print(f"[+] Extracting strings from {filepath} using memory mapping...")
    
    with open(filepath, 'rb') as f:
        # Memory-map the file for more efficient access
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            current = bytearray()
            
            for i in range(len(mm)):
                byte = mm[i]
                if 32 <= byte <= 126:  # Printable ASCII
                    current.append(byte)
                else:
                    if len(current) >= min_length:
                        yield current.decode('ascii', errors='ignore')
                    current = bytearray()
                    
            # Don't forget the last string if it ends at EOF
            if len(current) >= min_length:
                yield current.decode('ascii', errors='ignore')
                
            mm.close()
        except (ValueError, OSError):
            # Fallback to buffered reading if memory-mapping fails
            print("[!] Memory mapping failed, falling back to buffered reading")
            yield from extract_strings_buffered(filepath, min_length)


def _process_chunk(chunk_data: bytes, min_length: int = 4) -> List[str]:
    """Process a chunk of binary data to extract strings.
    
    Args:
        chunk_data: Binary data to process
        min_length: Minimum length of strings to extract
        
    Returns:
        List of extracted strings from this chunk
    """
    results = []
    current = bytearray()
    
    for byte in chunk_data:
        if 32 <= byte <= 126:  # Printable ASCII
            current.append(byte)
        else:
            if len(current) >= min_length:
                results.append(current.decode('ascii', errors='ignore'))
            current = bytearray()
    
    # Don't forget the last string if it ends at chunk boundary
    if len(current) >= min_length:
        results.append(current.decode('ascii', errors='ignore'))
        
    return results


def extract_strings_parallel(filepath: str, min_length: int = 4, 
                            chunk_size: int = 10 * 1024 * 1024) -> List[str]:
    """Extract printable ASCII strings from a binary file using parallel processing.
    
    Args:
        filepath: Path to the binary file
        min_length: Minimum length of strings to extract
        chunk_size: Size of each chunk to process in parallel
        
    Returns:
        List of extracted strings
    """
    print(f"[+] Extracting strings from {filepath} using parallel processing...")
    
    file_size = os.path.getsize(filepath)
    chunks = []
    
    # Split the file into chunks
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
    
    print(f"[+] Processing {len(chunks)} chunks in parallel...")
    
    # Process chunks in parallel
    results = []
    num_processes = min(mp.cpu_count(), len(chunks))
    
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(_process_chunk, chunk, min_length) for chunk in chunks]
        
        for i, future in enumerate(as_completed(futures)):
            chunk_results = future.result()
            results.extend(chunk_results)
            print(f"[+] Processed chunk {i+1}/{len(chunks)}: {len(chunk_results)} strings found")
    
    print(f"[+] Total extracted: {len(results)} strings")
    return results


def extract_strings(filepath: str, min_length: int = 4, method: str = "auto") -> List[str]:
    """Extract printable ASCII strings from a binary file using the specified method.
    
    Args:
        filepath: Path to the binary file
        min_length: Minimum length of strings to extract
        method: Extraction method to use: "auto", "buffered", "mmap", or "parallel"
        
    Returns:
        List of extracted strings
    """
    # Choose the appropriate method based on file size and system capabilities
    if method == "auto":
        file_size = os.path.getsize(filepath)
        
        if file_size < 100 * 1024 * 1024:  # < 100MB
            method = "mmap"
        else:
            # For larger files, use parallel processing if multiple cores available
            if mp.cpu_count() > 1:
                method = "parallel"
            else:
                method = "buffered"
    
    print(f"[+] Using {method} extraction method")
    
    if method == "mmap":
        return list(extract_strings_mmap(filepath, min_length))
    elif method == "parallel":
        return extract_strings_parallel(filepath, min_length)
    else:  # "buffered"
        return list(extract_strings_buffered(filepath, min_length))


def load_keys(path: str) -> List[str]:
    """Load decryption keys from configuration file.
    
    Args:
        path: Path to key file
        
    Returns:
        List of decryption keys
    """
    if not Path(path).exists():
        print(f"[!] Key file not found: {path}")
        return []
        
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]
