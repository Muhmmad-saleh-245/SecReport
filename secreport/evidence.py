"""Evidence vault: copy files into the engagement, hash them (SHA-256),
and re-verify later so the chain of custody can be shown to a client.

Security notes:
  * Stored names are sanitised, so a name like "../../x" cannot escape the vault.
  * Files are never executed or parsed here, only copied and hashed.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

from .models import Engagement, EvidenceItem, now_iso

VAULT_DIR = "evidence"
MAX_EVIDENCE_BYTES = 50 * 1024 * 1024


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_name(name: str) -> str:
    """Reduce any user-supplied name to a harmless single path component."""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name[:100] or "file"


def _next_id(eng: Engagement) -> str:
    nums = [int(m.group(1)) for e in eng.evidence if (m := re.fullmatch(r"E-(\d+)", e.id))]
    return f"E-{(max(nums) + 1 if nums else 1):03d}"


def _store(eng, eng_dir, data_path: Path, display_name: str, description, finding_ids):
    finding_ids = list(finding_ids or [])
    for fid in finding_ids:
        eng.get_finding(fid)  # raises KeyError if unknown
    size = data_path.stat().st_size
    if size > MAX_EVIDENCE_BYTES:
        raise ValueError(f"Evidence file is larger than {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB")
    vault = Path(eng_dir) / VAULT_DIR
    vault.mkdir(parents=True, exist_ok=True)
    evidence_id = _next_id(eng)
    clean = safe_name(display_name)
    stored_name = f"{evidence_id}_{clean}"
    dest = vault / stored_name
    shutil.copy2(data_path, dest)
    item = EvidenceItem(
        id=evidence_id, filename=clean, stored_as=f"{VAULT_DIR}/{stored_name}",
        sha256=sha256_file(dest), size=dest.stat().st_size,
        description=description, added_at=now_iso(), finding_ids=finding_ids,
    )
    eng.evidence.append(item)
    for fid in finding_ids:
        f = eng.get_finding(fid)
        if item.id not in f.evidence_ids:
            f.evidence_ids.append(item.id)
    return item


def add_file(eng: Engagement, eng_dir, source, description: str = "",
             finding_ids=None) -> EvidenceItem:
    """Copy `source` into <eng_dir>/evidence and record its hash."""
    source = Path(source)
    if not source.is_file():
        raise FileNotFoundError(f"Evidence file not found: {source}")
    return _store(eng, eng_dir, source, source.name, description, finding_ids)


def add_bytes(eng: Engagement, eng_dir, name: str, data: bytes,
              description: str = "", finding_ids=None) -> EvidenceItem:
    """Store uploaded bytes (used by the web UI)."""
    if len(data) > MAX_EVIDENCE_BYTES:
        raise ValueError(f"Evidence file is larger than {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB")
    vault = Path(eng_dir) / VAULT_DIR
    vault.mkdir(parents=True, exist_ok=True)
    tmp = vault / ".incoming.tmp"
    tmp.write_bytes(data)
    try:
        return _store(eng, eng_dir, tmp, name, description, finding_ids)
    finally:
        tmp.unlink(missing_ok=True)


def add_text(eng: Engagement, eng_dir, name: str, text: str,
             description: str = "", finding_ids=None) -> EvidenceItem:
    """Store pasted text (tool output, HTTP request/response) as evidence."""
    return add_bytes(eng, eng_dir, name, text.encode("utf-8"), description, finding_ids)


def path_of(eng: Engagement, eng_dir, evidence_id: str) -> Path:
    """Resolve a stored evidence file, refusing anything outside the vault."""
    for item in eng.evidence:
        if item.id == evidence_id:
            vault = (Path(eng_dir) / VAULT_DIR).resolve()
            path = (Path(eng_dir) / item.stored_as).resolve()
            if vault not in path.parents:
                raise ValueError("Evidence path escapes the vault")
            return path
    raise KeyError(f"No evidence {evidence_id}")


def verify(eng: Engagement, eng_dir) -> list:
    """Re-hash every stored file. Returns [(id, ok, detail), ...]."""
    results = []
    for item in eng.evidence:
        try:
            path = path_of(eng, eng_dir, item.id)
        except ValueError as exc:
            results.append((item.id, False, str(exc)))
            continue
        if not path.is_file():
            results.append((item.id, False, "file missing"))
            continue
        if sha256_file(path) == item.sha256:
            results.append((item.id, True, "hash matches"))
        else:
            results.append((item.id, False, "HASH MISMATCH, file was modified"))
    return results
