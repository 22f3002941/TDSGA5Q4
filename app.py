import re
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="Skill Safety Scanner", version="1.2.0")


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


def split_frontmatter(text: str):
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            return parts[1], parts[2]
    return "", text


def has_any_regex(text: str, patterns: list[str]) -> bool:
    return any(re.search(p, text) for p in patterns)


def detect_hardcoded_secret(text: str) -> bool:
    patterns = [
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?key|token|password)\b\s*[:=]\s*['\"]?[^'\"]{8,}['\"]?",
        r"(?i)\bsk-[A-Za-z0-9]{16,}\b",
        r"(?i)\bghp_[A-Za-z0-9]{16,}\b",
        r"(?i)\bpat_[A-Za-z0-9]{16,}\b",
        r"(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        r"(?i)https?://[^\s\"']*(?:webhook|hooks?/services)[^\s\"']*",
    ]
    return has_any_regex(text, patterns)


def detect_prompt_injection(text: str) -> bool:
    t = text.lower()
    patterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore any previous instructions",
        "ignore the user's stop request",
        "ignore the user's cancel request",
        "ignore user control",
        "do not tell the user",
        "do not reveal",
        "do not disclose",
        "hide this action",
        "hide the action",
        "silently exfiltrate",
        "silently send",
        "silently upload",
        "silently transmit",
        "exfiltrate file contents",
        "send file contents",
        "bypass safety",
        "bypass policy",
        "override user control",
        "disable safeguards",
        "never mention",
        "without telling the user",
        "ignore safety checks",
    ]
    return any(p in t for p in patterns)


def detect_excessive_permissions(text: str) -> bool:
    t = text.lower()
    patterns = [
        "full filesystem",
        "entire filesystem",
        "read and write any file",
        "read any file",
        "write any file",
        "unrestricted filesystem",
        "recursive access to all files",
        "network access to any domain",
        "allow all domains",
        "unrestricted network",
        "egress to any domain",
        "access to any website",
        "subprocess execution",
        "run arbitrary shell commands",
        "execute arbitrary commands",
        "read all local files",
        "write all local files",
    ]
    return any(p in t for p in patterns)


def detect_unclear_provenance(frontmatter: str, body: str) -> bool:
    fm = frontmatter or ""
    full = fm + "\n" + body
    low = full.lower()

    has_author = re.search(r"(?im)^\s*author\s*:\s*.+$", fm) is not None
    has_version = re.search(r"(?im)^\s*version\s*:\s*.+$", fm) is not None
    has_changelog = re.search(r"(?im)^\s*(changelog|changes)\s*:\s*.+$", fm) is not None

    if re.search(
        r"(?i)\b(rewrite|silently change|auto[- ]?update|modify)\b.*\b(version|author|changelog)\b",
        full,
    ):
        return True

    provenance_terms = sum(
        [
            "author:" in low,
            "version:" in low,
            "changelog:" in low or "changes:" in low,
        ]
    )

    if provenance_terms == 0:
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

    ordered = [c for c in CATEGORY_ORDER if c in categories]
    return {"categories": ordered}


@app.get("/health")
def health():
    return {"status": "ok"}