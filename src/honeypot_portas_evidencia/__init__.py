"""Honeypot de portas falsas com integridade de evidência (SHA-256)."""

from .evidence import EvidenceLog, compute_evidence_hash, verify_log
from .honeypot import ConnectionRecord, Honeypot

__all__ = [
    "ConnectionRecord",
    "EvidenceLog",
    "Honeypot",
    "compute_evidence_hash",
    "verify_log",
]

__version__ = "0.1.0"
