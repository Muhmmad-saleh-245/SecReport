"""Client branding assets. Only bounded PNG and JPEG logos are accepted."""

from __future__ import annotations

import base64
import re
import zlib
from pathlib import Path

MAX_LOGO_BYTES = 2 * 1024 * 1024
MAX_LOGO_PIXELS = 16_000_000
MAX_LOGO_DIMENSION = 8192
DEFAULT_COLOR = "#0f172a"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


class BrandingError(ValueError):
    """Raised when branding data is malformed or unsafe."""


def validate_color(value: str) -> str:
    value = (value or "").strip()
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
        raise BrandingError("Brand colour must be a six-digit hex value such as #1a2b3c")
    return value.lower()


def _dimensions(width: int, height: int) -> tuple[int, int]:
    if (not width or not height or width > MAX_LOGO_DIMENSION or height > MAX_LOGO_DIMENSION
            or width * height > MAX_LOGO_PIXELS):
        raise BrandingError("Logo dimensions are invalid or too large")
    return width, height


def inspect_logo(data: bytes) -> tuple[str, str, int, int]:
    """Validate file signature and structure; return (extension, MIME, width, height)."""
    if not isinstance(data, bytes) or not data:
        raise BrandingError("Logo file is empty or invalid")
    if len(data) > MAX_LOGO_BYTES:
        raise BrandingError("Logo file is larger than 2 MB")

    if data.startswith(PNG_SIGNATURE):
        pos = len(PNG_SIGNATURE)
        width = height = 0
        saw_idat = saw_iend = False
        while pos + 12 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], "big")
            end = pos + 12 + length
            if end > len(data):
                raise BrandingError("PNG logo is truncated")
            kind = data[pos + 4:pos + 8]
            chunk = data[pos + 8:pos + 8 + length]
            checksum = int.from_bytes(data[pos + 8 + length:end], "big")
            if zlib.crc32(kind + chunk) & 0xFFFFFFFF != checksum:
                raise BrandingError("PNG logo has an invalid checksum")
            if pos == len(PNG_SIGNATURE):
                if kind != b"IHDR" or length != 13:
                    raise BrandingError("PNG logo has an invalid header")
                width, height = int.from_bytes(chunk[:4], "big"), int.from_bytes(chunk[4:8], "big")
                _dimensions(width, height)
            elif kind == b"IHDR":
                raise BrandingError("PNG logo has a duplicate header")
            if kind == b"IDAT":
                saw_idat = True
            if kind == b"IEND":
                if length != 0 or end != len(data):
                    raise BrandingError("PNG logo has invalid trailing data")
                saw_iend = True
                break
            pos = end
        if not (width and height and saw_idat and saw_iend):
            raise BrandingError("PNG logo is incomplete")
        return "png", "image/png", width, height

    if data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9"):
        pos = 2
        width = height = 0
        saw_scan = False
        while pos < len(data) - 2:
            if data[pos] != 0xFF:
                raise BrandingError("JPEG logo has an invalid marker")
            while pos < len(data) and data[pos] == 0xFF:
                pos += 1
            if pos >= len(data):
                break
            marker = data[pos]
            pos += 1
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
                continue
            if pos + 2 > len(data):
                break
            length = int.from_bytes(data[pos:pos + 2], "big")
            end = pos + length
            if length < 2 or end > len(data):
                raise BrandingError("JPEG logo has an invalid segment")
            if marker in JPEG_SOF:
                if length < 8:
                    raise BrandingError("JPEG logo has an invalid frame")
                height = int.from_bytes(data[pos + 3:pos + 5], "big")
                width = int.from_bytes(data[pos + 5:pos + 7], "big")
                _dimensions(width, height)
            if marker == 0xDA:
                saw_scan = True
                break
            pos = end
        if not (width and height and saw_scan):
            raise BrandingError("JPEG logo is incomplete")
        return "jpg", "image/jpeg", width, height

    raise BrandingError("Logo must be a PNG or JPEG image; SVG and other file types are not supported")


def save_logo(eng_dir, data: bytes) -> str:
    extension, _, _, _ = inspect_logo(data)
    root = Path(eng_dir).resolve()
    directory = root / "branding"
    directory.mkdir(parents=True, exist_ok=True)
    if directory.resolve().parent != root:
        raise BrandingError("Branding directory escapes the engagement")
    destination = directory / f"logo.{extension}"
    temporary = directory / f".logo.{extension}.tmp"
    if temporary.is_symlink():
        raise BrandingError("Temporary logo path is not a regular file")
    temporary.write_bytes(data)
    temporary.replace(destination)
    for old in directory.glob("logo.*"):
        if old != destination and old.is_file():
            old.unlink()
    return f"branding/{destination.name}"


def remove_logo(eng_dir, relative_path: str) -> None:
    if relative_path not in ("branding/logo.png", "branding/logo.jpg"):
        raise BrandingError("Stored logo path is invalid")
    root = Path(eng_dir).resolve()
    path = (root / relative_path).resolve()
    if root not in path.parents:
        raise BrandingError("Stored logo path escapes the engagement")
    path.unlink(missing_ok=True)


def logo_data_uri(eng, eng_dir) -> str:
    relative_path = getattr(eng, "brand_logo_path", "")
    if not relative_path:
        return ""
    if relative_path not in ("branding/logo.png", "branding/logo.jpg"):
        raise BrandingError("Stored logo path is invalid")
    root = Path(eng_dir).resolve()
    path = (root / relative_path).resolve()
    if root not in path.parents:
        raise BrandingError("Stored logo path escapes the engagement")
    data = path.read_bytes()
    _, mime, _, _ = inspect_logo(data)
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"