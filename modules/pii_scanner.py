"""pii_scanner.py - Rule-based runtime safeguards for prompts and model outputs.

Implements the runtime protections recommended for deployed GenAI systems
(sanitize user inputs, filter outputs) using simple regular expressions.
No machine learning and no external service is used. Use synthetic text only.
"""
import re

from modules import risk_engine as engine

# (label, compiled regex, category, placeholder). ORDER MATTERS: earlier rules win overlaps.
_RULES = [
    ("Email address", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "Personal", "[EMAIL]"),
    ("Payment card number", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), "Sensitive", "[CARD]"),
    ("Credential / OTP / CVV", re.compile(r"\b(?:password|passwd|pwd|otp|cvv|pin)\b\s*(?:is|:|=)?\s*[^\s,;.]+", re.I),
     "Sensitive", "[SECRET]"),
    ("Aadhaar-format ID", re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"), "Sensitive", "[GOV_ID]"),
    ("PAN-format tax ID", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "Sensitive", "[PAN]"),
    ("Date of birth", re.compile(r"\b(?:dob|date of birth|born on)\b\s*[:\-]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", re.I),
     "Sensitive", "[DOB]"),
    ("Phone number", re.compile(r"(?<!\w)(?:\+\d{1,3}[ -]?\d{3,5}[ -]?\d{4,6}|(?:\+?91[ -]?)?[6-9]\d{9})(?!\w)"),
     "Personal", "[PHONE]"),
    ("IP address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "Personal", "[IP]"),
    ("Person name", re.compile(r"\b[Mm]y name is\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)"), "Personal", "[NAME]"),
]


def luhn_ok(text):
    """Luhn checksum used by real card numbers; avoids flagging random digit strings."""
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def _valid(label, value):
    if label == "Payment card number":
        return luhn_ok(value)
    if label == "IP address":
        return all(int(p) <= 255 for p in value.split("."))
    return True


def detect(text):
    """Return a list of detected entities (type, category, text, start, end)."""
    found, taken = [], []
    for label, rx, category, _ in _RULES:
        for m in rx.finditer(text or ""):
            start, end = m.span(1) if m.lastindex else m.span()
            value = text[start:end]
            if not _valid(label, value):
                continue
            if any(start < e and end > s for s, e in taken):  # overlaps a stronger match
                continue
            taken.append((start, end))
            found.append({"type": label, "category": category, "text": value, "start": start, "end": end})
    return sorted(found, key=lambda e: e["start"])


def redact(text, entities=None):
    """Replace every detected item with a placeholder such as [EMAIL]."""
    entities = detect(text) if entities is None else entities
    placeholder = {label: ph for label, _, _, ph in _RULES}
    for e in sorted(entities, key=lambda x: -x["start"]):
        text = text[:e["start"]] + placeholder[e["type"]] + text[e["end"]:]
    return text


def exposure_score(sensitive, personal):
    """0-100 exposure score = min(100, 25 x sensitive items + 10 x personal items)."""
    return min(100, 25 * sensitive + 10 * personal)


def exposure_level(score):
    return "None detected" if score == 0 else engine.overall_label(score)


def scan(text):
    """Scan one text and return entities, redacted text and an exposure score."""
    ents = detect(text)
    sens = sum(e["category"] == "Sensitive" for e in ents)
    pers = len(ents) - sens
    counts = {}
    for e in ents:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
    redacted = redact(text, ents)
    score = exposure_score(sens, pers)
    return {"entities": ents, "counts": counts, "sensitive": sens, "personal": pers,
            "exposure_score": score, "level": exposure_level(score), "redacted": redacted,
            "after_redaction_score": scan_score_only(redacted)}


def scan_score_only(text):
    ents = detect(text)
    sens = sum(e["category"] == "Sensitive" for e in ents)
    return exposure_score(sens, len(ents) - sens)


def summary(target, result, when):
    """Compact record that is safe to store (no raw text is persisted)."""
    return {"time": when, "target": target, "counts": result["counts"], "sensitive": result["sensitive"],
            "personal": result["personal"], "exposure_score": result["exposure_score"],
            "after_redaction_score": result["after_redaction_score"]}
