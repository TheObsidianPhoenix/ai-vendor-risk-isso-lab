"""Resource limits for untrusted files (SR-14, TR-06, TR-10).

A vendor file is attacker-controlled input. These limits keep one bad file
from exhausting memory or time. The pypdf alerts fixed in pull request #4
were all of this kind: crafted PDFs that loop forever or use huge memory.
Patching the library fixes known flaws; these limits contain unknown ones.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 10 * 1024 * 1024        # FR-02: 10 MB per file
    max_pdf_pages: int = 100
    max_seconds: float = 20.0                     # Whole scan, enforced by a separate process
    max_zip_entries: int = 1_000                  # XLSX and DOCX are zip archives
    max_uncompressed_bytes: int = 100 * 1024 * 1024
    max_compression_ratio: int = 100              # Zip-bomb guard for any single entry
    min_extracted_chars: int = 20                 # Less than this = image-only document (decision D-04)
    max_excerpt_chars: int = 160                  # How much suspicious text a flag may quote


DEFAULT_LIMITS = Limits()
