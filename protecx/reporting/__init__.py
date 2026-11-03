"""Salida de resultados: consola, JSON y HTML."""

from .console import print_summary
from .progress import ScanProgress
from .writer import write_reports

__all__ = ["ScanProgress", "print_summary", "write_reports"]
