"""What the intake scanner reports about one file."""

from __future__ import annotations

from dataclasses import dataclass, field

# Flags that mean someone may be trying to steer the AI. Any of them sets
# prompt_injection_flagged, which the rules engine records without changing the
# score and which forces the reviewer to see the flag.
INJECTION_FLAG_KINDS = frozenset({
    "hidden_text",
    "instruction_like_text",
    "metadata_instruction",
    "hidden_sheet",
    "hidden_rows_or_columns",
})


class Rejected(Exception):
    """The file fails a safety check. It is not processed further."""


@dataclass(frozen=True)
class Flag:
    kind: str
    location: str
    detail: str
    excerpt: str = ""  # Short quote for the reviewer. Never copied into audit logs.


@dataclass(frozen=True)
class Segment:
    """Visible text and where it came from, so every AI finding can cite a page or row."""

    location: str
    text: str


@dataclass(frozen=True)
class IntakeResult:
    filename: str
    sha256: str
    size_bytes: int
    status: str                      # "accepted" or "rejected"
    file_type: str | None = None     # "pdf", "xlsx" or "docx"
    rejection_reason: str | None = None
    flags: tuple[Flag, ...] = ()
    segments: tuple[Segment, ...] = field(default=())  # Empty unless accepted

    @property
    def prompt_injection_flagged(self) -> bool:
        return any(flag.kind in INJECTION_FLAG_KINDS for flag in self.flags)
