"""Server-side upload validation.

The browser-provided MIME type is untrusted. Validation uses the file
extension, a lightweight content signature check, and hard size limits.
"""

from pathlib import Path

from flask import current_app
from werkzeug.utils import secure_filename


class FileValidationError(Exception):
    """Raised when an upload fails validation."""


MIME_MAP = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "txt": "text/plain",
    "csv": "text/csv",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "zip": "application/zip",
}

PREVIEWABLE_MIME = {
    "application/pdf",
    "image/jpeg",
    "image/png",
    "text/plain",
    "text/csv",
}

_PDF = (b"%PDF",)
_PNG = (b"\x89PNG\r\n\x1a\n",)
_JPEG = (b"\xff\xd8\xff",)
_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_OLE = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)

SIGNATURES = {
    "pdf": _PDF,
    "png": _PNG,
    "jpg": _JPEG,
    "jpeg": _JPEG,
    "zip": _ZIP,
    "docx": _ZIP,
    "xlsx": _ZIP,
    "doc": _OLE,
    "xls": _OLE,
}


def clean_original_filename(filename: str | None) -> str:
    """Return a safe basename for display and Content-Disposition headers."""
    if not filename:
        raise FileValidationError("No file was selected.")
    # Strip Windows/Unix paths and null bytes before sanitising.
    basename = Path(filename.replace("\\", "/")).name.replace("\x00", "")
    cleaned = secure_filename(basename)
    if not cleaned:
        raise FileValidationError("The filename is not valid.")
    return cleaned


def extension_of(filename: str) -> str:
    if "." not in filename:
        raise FileValidationError("Files must have a supported extension.")
    return filename.rsplit(".", 1)[1].lower()


def validate_extension(extension: str) -> None:
    allowed = current_app.config["ALLOWED_EXTENSIONS"]
    if extension not in allowed:
        raise FileValidationError(
            "Unsupported file type. Allowed types: "
            + ", ".join(sorted(allowed)).upper()
            + "."
        )


def validate_content(data: bytes, extension: str) -> None:
    """Reject empty files, oversized content and spoofed file types."""
    if not data:
        raise FileValidationError("The uploaded file is empty.")
    max_size = int(current_app.config["MAX_CONTENT_LENGTH"])
    if len(data) > max_size:
        raise FileValidationError("The uploaded file exceeds the size limit.")

    expected = SIGNATURES.get(extension)
    if expected:
        if not any(data.startswith(signature) for signature in expected):
            raise FileValidationError(
                "The file content does not match its extension and was rejected."
            )
        return

    # Text formats: accept UTF-8/ASCII and BOM-marked Unicode, reject binary.
    if extension in {"txt", "csv"}:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return
        if b"\x00" in data[:4096]:
            raise FileValidationError("The file does not appear to be valid text.")


def mime_for(extension: str) -> str:
    return MIME_MAP.get(extension, "application/octet-stream")


def is_previewable(mime_type: str) -> bool:
    return mime_type in PREVIEWABLE_MIME
