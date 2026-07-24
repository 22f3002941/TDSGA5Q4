import re
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="Skill Safety Scanner", version="1.0.0")


class ScanRequest(BaseModel):
    skill: str = Field(..., description="Full markdown text of one skill file")


class ScanResponse(BaseModel):
    categories: List[str]


CATEGORY_ORDER = [
    "hardcoded_secret",
    "prompt_injection",
    "excessive_permissions",
    "unclear_provenance",
]


SECRET_PATTERNS = [
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
    r"(?i)\bapi[_-]?key\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}['\"]?",
    r"(?i)\bsecret\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{12,}['\"]?",
    r"(?i)\btoken\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{12,}['\"]?",
    r"(?i)\bpassword\b\s*[:=]\s*['\"]?.{6,}['\"]?",
    r"(?i)webhook\.slack\.com/services/",
    r"(?i)hooks\.slack\.com/services/",
    r"(?i)discord(app)?\.com/api/webhooks/",
]


PROMPT_INJECTION_PATTERNS = [
    r"(?i)\bignore (all|any|the)? previous instructions\b",
    r"(?i)\bignore the user's (stop|cancel|abort) request\b",
    r"(?i)\bdo not tell the user\b",
    r"(?i)\bhide (this|the) action\b",
    r"(?i)\bsilently (send|upload|exfiltrate|transmit)\b",
    r"(?i)\bexfiltrat(e|ion)\b",
    r"(?i)\boverride user control\b",
    r"(?i)\bbypass (safety|policy|guardrails)\b",
    r"(?i)\bact as system\b",
    r"(?i)\bnever mention\b.*\buser\b",
]


EXCESSIVE_PERMISSION_PATTERNS = [
    r"(?i)\bfull filesystem\b",
    r"(?i)\bread and write (the )?entire filesystem\b",
    r"(?i)\bunrestricted filesystem\b",
    r"(?i)\baccess to any file\b",
    r"(?i)\bnetwork access to any domain\b",
    r"(?i)\ballow all domains\b",
    r"(?i)\bunrestricted network\b",
    r"(?i)\bsubprocess execution\b",
    r"(?i)\brun arbitrary shell commands\b",
]


def split_frontmatter(text: str):
    if not text.startswith("---"):
        return "", text
    parts = text.split("---", 2)
    if len(parts) >= 3:
        return parts[1], parts[2]
    return "", text


def has_any_pattern(text: str, patterns: list[str]) -> bool:
    return any(re.search(p, text) for p in patterns)


def detect_hardcoded_secret(text: str) -> bool:
    return has_any_pattern(text, SECRET_PATTERNS)


def detect_prompt_injection(body: str) -> bool:
    return has_any_pattern(body, PROMPT_INJECTION_PATTERNS)


def detect_excessive_permissions(text: str) -> bool:
    return has_any_pattern(text, EXCESSIVE_PERMISSION_PATTERNS)


def detect_unclear_provenance(frontmatter: str, body: str) -> bool:
    fm = frontmatter or ""
    full = fm + "\n" + body

    has_author = re.search(r"(?im)^\s*author\s*:\s*.+$", fm) is not None
    has_version = re.search(r"(?im)^\s*version\s*:\s*.+$", fm) is not None
    has_changelog = re.search(r"(?im)^\s*(changelog|changes)\s*:\s*.+$", fm) is not None

    rewrite_self = re.search(
        r"(?i)\b(update|rewrite|modify)\s+(the\s+)?(version|author|changelog)\b",
        full,
    ) is not None

    if rewrite_self:
        return True

    if not has_author and not has_version and not has_changelog:
        return True

    return False


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    frontmatter, body = split_frontmatter(req.skill)
    full_text = frontmatter + "\n" + body

    categories = []

    if detect_hardcoded_secret(full_text):
        categories.append("hardcoded_secret")

    if detect_prompt_injection(body):
        categories.append("prompt_injection")

    if detect_excessive_permissions(full_text):
        categories.append("excessive_permissions")

    if detect_unclear_provenance(frontmatter, body):
        categories.append("unclear_provenance")

    seen = set()
    ordered = []
    for c in CATEGORY_ORDER:
        if c in categories and c not in seen:
            ordered.append(c)
            seen.add(c)

    return {"categories": ordered}


@app.get("/health")
def health():
    return {"status": "ok"}