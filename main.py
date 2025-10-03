from __future__ import annotations
import argparse
import csv
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# find_username_refs.py — Search your filesystem for occurrences of a username (or any string)
# inside text-like files only, with sensible binary detection and performance safeguards.
#
# Usage examples (Windows):
#   python find_username_refs.py --root C:\ --needle OldName --out results.csv
#   python find_username_refs.py --root C:\Users\NewName --needle OldName --ext-add .cs,.sln --ci
#
# Key features:
# - Heuristic text detection (BOM check, NUL-byte check, printable-ratio threshold)
# - Tries common encodings (utf-8/utf-16/latin-1) automatically
# - Extension allowlist to always treat as text (configurable)
# - Skips likely-binary files and very large files by default
# - Parallel, I/O-bound scanning with graceful error handling
# - CSV output with file, line number, and excerpt (no PII leakage beyond your own needle)
#
# NOTE: Run from an elevated prompt if you want to traverse protected folders.

# -------------------------
# Defaults / heuristics
# -------------------------
DEFAULT_MAX_BYTES = 32 * 1024 * 1024  # 32 MiB per file safety cap (override with --max-bytes)
PRINTABLE_THRESHOLD = 0.85  # For heuristic text detection
CHUNK_SIZE = 8192  # For initial sniff + streaming

# Common text extensions; always treated as text if matched
DEFAULT_TEXT_EXTS = {
    ".txt", ".md", ".rst", ".csv", ".tsv", ".log",
    ".json", ".xml", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".toml",
    ".bat", ".cmd", ".ps1", ".reg", ".vbs", ".vb", ".ahk",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".java", ".rb", ".go", ".rs",
    ".py", ".pyw", ".r", ".m", ".php", ".pl", ".lua", ".sh", ".zsh",
    ".swift", ".kt", ".kts", ".scala", ".groovy",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".css", ".scss", ".less",
    ".html", ".htm", ".xhtml", ".svg",
    ".tex", ".srt", ".ass", ".properties", ".gradle", ".ini",
    ".sln", ".csproj", ".vcxproj", ".props", ".targets", ".cmake",
    ".dockerfile", ".env",
}

# Directories to skip by default on Windows to keep noise down / avoid loops
DEFAULT_EXCLUDES = {
    r"C:\\Windows",
    r"C:\\Program Files",
    r"C:\\Program Files (x86)",
    r"C:\\ProgramData",
    r"C:\\$Recycle.Bin",
    r"C:\\Recovery",
    r"C:\\System Volume Information",
}


# -------------------------
# Helpers
# -------------------------

def normalize_extset(exts: Iterable[str]) -> set[str]:
    s = set()
    for e in exts:
        e = e.strip()
        if not e:
            continue
        if not e.startswith('.'):
            e = '.' + e
        s.add(e.lower())
    return s


def is_probably_text(path: Path, forced_text_exts: set[str]) -> bool:
    """Return True if file looks texty enough to scan.
    Strategy:
      - Whitelist by extension
      - Check BOMs
      - NUL byte => binary
      - Printable ASCII ratio in first chunk
    """
    try:
        ext = path.suffix.lower()
        if ext in forced_text_exts:
            return True
        with path.open('rb') as f:
            head = f.read(CHUNK_SIZE)
        if not head:
            return True  # empty files are "text"
        # Common BOMs
        if head.startswith(b"\xef\xbb\xbf"):
            return True  # UTF-8 BOM
        if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
            return True  # UTF-16 LE/BE
        if head.startswith(b"\xff\xfe\x00\x00") or head.startswith(b"\x00\x00\xfe\xff"):
            return True  # UTF-32 LE/BE
        if b"\x00" in head:
            return False
        # Printable ratio
        printable = set(range(32, 127)) | {9, 10, 13}  # tab, LF, CR
        pr = sum(1 for b in head if b in printable) / len(head)
        return pr >= PRINTABLE_THRESHOLD
    except Exception:
        return False


def pick_encoding(head: bytes) -> str:
    # Detect from BOMs; else try utf-8 then cp1252 as a last resort
    if head.startswith(b"\xef\xbb\xbf"):
        return 'utf-8-sig'
    if head.startswith(b"\xff\xfe\x00\x00"):
        return 'utf-32-le'
    if head.startswith(b"\x00\x00\xfe\xff"):
        return 'utf-32-be'
    if head.startswith(b"\xff\xfe"):
        return 'utf-16-le'
    if head.startswith(b"\xfe\xff"):
        return 'utf-16-be'
    try:
        head.decode('utf-8')
        return 'utf-8'
    except Exception:
        return 'cp1252'


def scan_file(path: Path, needle: str, ci: bool, max_bytes: int, forced_text_exts: set[str]) -> List[Tuple[int, str]]:
    """Return list of (line_number, line_excerpt) with matches for needle.
    Skips binary/too-large files. Does not raise on decode errors.
    """
    try:
        if path.is_symlink():
            return []
        if path.stat().st_size > max_bytes:
            return []
        if not is_probably_text(path, forced_text_exts):
            return []
        with path.open('rb') as f:
            head = f.read(CHUNK_SIZE)
        enc = pick_encoding(head)
        # Stream lines with chosen encoding; ignore undecodable bytes
        matches: List[Tuple[int, str]] = []
        if ci:
            n = needle.lower()
            with path.open('r', encoding=enc, errors='ignore') as tf:
                for i, line in enumerate(tf, 1):
                    if n in line.lower():
                        excerpt = line.strip()
                        if len(excerpt) > 300:
                            excerpt = excerpt[:297] + '...'
                        matches.append((i, excerpt))
        else:
            with path.open('r', encoding=enc, errors='ignore') as tf:
                for i, line in enumerate(tf, 1):
                    if needle in line:
                        excerpt = line.strip()
                        if len(excerpt) > 300:
                            excerpt = excerpt[:297] + '...'
                        matches.append((i, excerpt))
        return matches
    except Exception:
        return []


def iter_files(root: Path, excludes: set[Path]) -> Iterable[Path]:
    """Walk the tree from root, skipping excluded directories and symlinked dirs."""
    # Normalize excludes to absolute, case-insensitive on Windows
    ex_norm = {Path(str(p)).resolve().as_posix().lower() for p in excludes}
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        # Skip reparse/links
        try:
            # Remove symlinked dirs from traversal
            dirnames[:] = [d for d in dirnames
                           if not Path(dirpath, d).is_symlink()
                           and Path(dirpath, d).resolve().as_posix().lower() not in ex_norm]
        except Exception:
            pass
        for name in filenames:
            p = Path(dirpath) / name
            yield p


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Search text-like files for a string.")
    p.add_argument('--root', required=True, help='Root folder to scan (e.g., C:\\ or C:\\Users\\YourName)')
    p.add_argument('--needle', required=True, help='String to search for (e.g., old username)')
    p.add_argument('--ci', action='store_true', help='Case-insensitive search')
    p.add_argument('--max-bytes', type=int, default=DEFAULT_MAX_BYTES,
                   help='Skip files larger than this many bytes (default: 32 MiB)')
    p.add_argument('--ext-add', type=str, default='',
                   help='Comma-separated extensions to always treat as text (e.g., .log,.cfg)')
    p.add_argument('--exclude', type=str, default='', help='Comma-separated absolute directories to exclude')
    p.add_argument('--workers', type=int, default=min(32, (os.cpu_count() or 4) * 4),
                   help='Number of parallel worker threads')
    p.add_argument('--out', type=str, default='username_hits.csv', help='CSV output path')
    p.add_argument('--quiet', action='store_true', help='Less console output')
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    now = datetime.now()
    args = parse_args(argv)
    root = Path(args.root)
    if not root.exists():
        print(f"Root not found: {root}", file=sys.stderr)
        return 2

    forced_text_exts = normalize_extset(DEFAULT_TEXT_EXTS | normalize_extset(args.ext_add.split(',')))

    excludes = set()
    if os.name == 'nt':
        # Add Windows defaults if scanning a drive root
        try:
            root_drive = root.anchor.lower()
        except Exception:
            root_drive = ''
        if root_drive and root.as_posix().lower() == root_drive.lower():
            excludes |= {Path(p) for p in DEFAULT_EXCLUDES}
    # User-provided excludes
    if args.exclude:
        excludes |= {Path(p.strip()) for p in args.exclude.split(',') if p.strip()}

    needle = args.needle

    if not args.quiet:
        print(f"Scanning from: {root}")
        if excludes:
            print("Excluding:")
            for e in sorted({str(p) for p in excludes}):
                print(f"  - {e}")
        print(f"Max file size: {args.max_bytes} bytes | Case-insensitive: {args.ci}")
        print(f"Workers: {args.workers} | Output: {args.out}")
        print("Starting… this may take a while on large trees.\n")

    files_iter = iter_files(root, excludes)

    hits_total = 0
    files_with_hits = 0
    results_rows: List[Tuple[str, int, int, str]] = []  # (file, line_no, count_in_line, excerpt)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        future_map = {ex.submit(scan_file, p, needle, args.ci, args.max_bytes, forced_text_exts): p for p in files_iter}
        for fut in as_completed(future_map):
            path = future_map[fut]
            try:
                matches = fut.result()
            except Exception:
                continue
            if matches:
                files_with_hits += 1
                for (ln, excerpt) in matches:
                    # Count occurrences in the line (respect case-insensitivity flag)
                    if args.ci:
                        count = excerpt.lower().count(needle.lower())
                    else:
                        count = excerpt.count(needle)
                    hits_total += count
                    results_rows.append((str(path), ln, count, excerpt))
                if not args.quiet:
                    print(f"[HIT] {path} ({len(matches)} matching line(s))")

    # Write CSV
    try:
        out_path = Path(args.out)
        with out_path.open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["file", "line", "count_in_line", "excerpt"])
            w.writerows(results_rows)

        print(f"\nWrote {len(results_rows)} matches from {files_with_hits} files to: {out_path}")
    except Exception as e:
        print(f"Failed to write CSV: {e}", file=sys.stderr)

    print(f"Total hits: {hits_total}")
    print(f"Finished in {datetime.now() - now}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
