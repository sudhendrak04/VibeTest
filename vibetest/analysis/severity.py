"""Category → CWE / OWASP-2025 / default-severity map.

Single source of truth for how our checklist categories map to standard
taxonomies (the paper's taxonomy table is generated from this).
"""
from __future__ import annotations

CATEGORY_MAP: dict[str, dict[str, str]] = {
    # Layer 1 — passive baseline
    "missing-security-header": {"cwe": "CWE-693", "owasp": "A02:2025", "severity": "low"},
    "exposed-sensitive-file": {"cwe": "CWE-538", "owasp": "A02:2025", "severity": "high"},
    "secret-in-bundle": {"cwe": "CWE-798", "owasp": "A04:2025", "severity": "critical"},
    "vulnerable-dependency": {"cwe": "CWE-1104", "owasp": "A03:2025", "severity": "high"},
    "cors-misconfiguration": {"cwe": "CWE-942", "owasp": "A02:2025", "severity": "medium"},
    "tls-issue": {"cwe": "CWE-319", "owasp": "A04:2025", "severity": "medium"},
    # Layer 2 — vibe-coding-specific
    "supabase-rls-missing": {"cwe": "CWE-862", "owasp": "A01:2025", "severity": "critical"},
    "supabase-rls-permissive": {"cwe": "CWE-863", "owasp": "A01:2025", "severity": "critical"},
    "service-role-key-exposed": {"cwe": "CWE-798", "owasp": "A04:2025", "severity": "critical"},
    "firebase-rules-open": {"cwe": "CWE-862", "owasp": "A01:2025", "severity": "critical"},
    "source-map-exposed": {"cwe": "CWE-200", "owasp": "A02:2025", "severity": "low"},
    "debug-config": {"cwe": "CWE-489", "owasp": "A02:2025", "severity": "medium"},
    "client-side-authz": {"cwe": "CWE-602", "owasp": "A01:2025", "severity": "high"},
}


def defaults_for(category: str) -> dict[str, str]:
    return CATEGORY_MAP.get(category, {})
