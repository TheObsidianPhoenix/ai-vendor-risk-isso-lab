"""Intake scanner: checks every uploaded file before anything else reads it."""

from .limits import DEFAULT_LIMITS, Limits
from .result import Flag, IntakeResult, Segment
from .scanner import detect_type, run_with_time_limit, scan_file

__all__ = ["DEFAULT_LIMITS", "Flag", "IntakeResult", "Limits", "Segment", "detect_type", "run_with_time_limit", "scan_file"]
