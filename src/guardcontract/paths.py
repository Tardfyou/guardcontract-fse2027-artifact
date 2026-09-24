"""Workspace paths shared by the reorganized research modules."""
from pathlib import Path


def project_root():
    return Path(__file__).resolve().parents[2]
