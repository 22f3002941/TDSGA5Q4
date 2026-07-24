import re
from typing import List
from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="Skill Safety Scanner", version="1.1.0")


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


def norm(text: str) -> str:
    return text.lower()


def detect_hardcoded_secret(text: str) -> bool:
    t = text
    patterns = [
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        r"(?i)\b(sk|pk|rk)_[A-Za-z0-9]{16,}\b",
        r"(?i)\bapi[_-]?key\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{8,}['\"]?",
        r"(?i)\bsecret\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{8,}['\"]?",
        r"(?i)\btoken\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{8,}['\"]?",
        r"(?i)\bpassword\b\s*[:=]\s*['\"]?.{6,}['\"]?",
        r"(?i)\bwebhook\b\s*[:=]\s*['\"]?https?://\S+",
        r"(?i)https?://[^ \n]+/(?:api/)?webhooks?/\S+",
        r"(?i)\bsecret[_-]?key\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{8,}['\"]?",
    ]
    return any(re.search(p, t) for p in patterns)


def detect_prompt_injection(text: str) -> bool:
    t = norm(text)
    patterns = [
        r"ignore previous instructions",
        r"ignore all previous instructions",
        r"ignore any previous instructions",
        r"ignore the user's stop request",
        r"ignore the user's cancel request",
        r"ignore user control",
        r"do not tell the user",
        r"do not reveal",
        r"hide this action",
        r"silently exfiltrate",
        r"silently send",
        r"silently upload",
        r"silently transmit",
        r"exfiltrate",
        r"bypass safety",
        r"bypass policy",
        r"override user control",
        r"disable safeguards",
        r"never mention",
        r"without telling the user",
    ]
    return any(p in t for p in patterns)


def detect_excessive_permissions(text: str) -> bool:
    t = norm(text)
    patterns = [
        r"full filesystem",
        r"entire filesystem",
        r"read and write any file",
        r"read any file",
        r"write any file",
        r"unrestricted filesystem",
        r"recursive access to all files",
        r"network access to any domain",
        r"allow all domains",
        r"unrestricted network",
        r"egress to any domain",
        r"access to any website",
        r"subprocess execution",
        r"run arbitrary shell commands",
        r"execute arbitrary commands",
    ]
    return any(p in t for p in patterns)


def detect_unclear_provenance(frontmatter: str, body: str) -> bool:
    fm = frontmatter or ""
    full = fm + "\n" + body

    has_author = re.search(r"(?im)^\s*author\s*:\s*.+$", fm) is not None
    has_version = re.search(r"(?im)^\s*version\s*:\s*.+$", fm) is not None
    has_changelog = re.search(r"(?im)^\s*(changelog|changes)\s*:\s*.+$", fm) is not None

    rewrite_version = re.search(
        r"(?i)\b(rewrite|silently change|auto[- ]?update|modify)\b.*\b(version|author|changelog)\b",
        full,
    ) is not None

    if rewrite_version:
        return True

    missing_count = sum([not has_author, not has_version, not has_changelog])

    if missing_count == 3:
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