"""Secret and PII masking (Task 1.5). Presidio (small spaCy model) for emails and phone numbers,
regexes for secrets. Replacements never span lines, so line numbers in masked code stay correct.
"""
from __future__ import annotations

import re
from functools import lru_cache

EMAIL = "<EMAIL>"
PHONE = "<PHONE>"
SECRET = "<SECRET>"

# (label, pattern, replacement). Each pattern stays within one line.
_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{15,}"), SECRET),
    ("aws_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), SECRET),
    ("url_password", re.compile(r"(?<=://)([^:/@\s'\"]+):([^@\s'\"]+)@"), r"\1:" + SECRET + "@"),
    ("secret_assignment", re.compile(
        r"(?i)\b(\w*(?:secret|password|passwd|token|api_?key|access_key)\w*)(\s*[=:]\s*)(['\"])(?!<SECRET>)([^'\"\n]{6,})\3"),
     r"\1\2\3" + SECRET + r"\3"),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*"), "Bearer " + SECRET),
]
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


@lru_cache
def _analyzer():
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_analyzer.predefined_recognizers import EmailRecognizer, PhoneRecognizer

    nlp = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]}).create_engine()
    registry = RecognizerRegistry(supported_languages=["en"])
    registry.add_recognizer(EmailRecognizer())
    registry.add_recognizer(PhoneRecognizer(supported_regions=("SG", "US", "GB", "IN", "AU", "MY")))
    return AnalyzerEngine(nlp_engine=nlp, registry=registry, supported_languages=["en"])


def mask(text: str, use_presidio: bool = True) -> tuple[str, dict[str, int]]:
    """Return (masked_text, counts per kind)."""
    counts: dict[str, int] = {}
    for label, pattern, repl in _SECRET_PATTERNS:
        text, n = pattern.subn(repl, text)
        if n:
            counts[label] = counts.get(label, 0) + n
    text, n = _EMAIL_RE.subn(EMAIL, text)
    if n:
        counts["email"] = n
    if use_presidio and text.strip():
        spans = [r for r in _analyzer().analyze(text=text, language="en", entities=["EMAIL_ADDRESS", "PHONE_NUMBER"])
                 if r.score >= 0.4]
        for r in sorted(spans, key=lambda r: r.start, reverse=True):
            chunk = text[r.start:r.end]
            if "\n" in chunk or chunk.startswith("<"):
                continue
            label = "email" if r.entity_type == "EMAIL_ADDRESS" else "phone"
            text = text[:r.start] + (EMAIL if label == "email" else PHONE) + text[r.end:]
            counts[label] = counts.get(label, 0) + 1
    return text, counts


def scrub(text: str) -> str:
    """Cheap regex-only masking for logs (no NLP model)."""
    return mask(text, use_presidio=False)[0]


def find_leaks(text: str, canaries: list[str]) -> list[str]:
    """Which planted canary values appear verbatim in text (used by the leak scanner)."""
    return [c for c in canaries if c and c in text]
