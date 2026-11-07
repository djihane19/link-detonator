"""Decodes QR codes from one untrusted image. Runs inside a disposable sandbox with
no network: the image arrives on stdin, one JSON object leaves on stdout.

It never opens, resolves or contacts a decoded payload. It only reads pixels.
"""

from __future__ import annotations

import base64
import io
import json
import signal
import sys

MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_SIDE = 4096
MAX_PIXELS = 16_000_000
MAX_CODES = 5
MAX_PAYLOAD_CHARS = 4096
PREVIEW_SIDE = 512
TIME_LIMIT_S = 8
FORMATS = {"PNG": "png", "JPEG": "jpeg", "WEBP": "webp"}


def reply(**data: object) -> None:
    sys.stdout.write(json.dumps(data, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def fail(reason: str) -> None:
    reply(ok=False, error=reason)
    sys.exit(0)


def on_timeout(_signum: int, _frame: object) -> None:
    fail("decoding took too long")


class DecodeError(Exception):
    """A refusal with one of the fixed reasons above. Raised by decode_image()."""


def decode_image(data: bytes, preview: bool = True) -> dict[str, object]:
    """Reads QR codes from image bytes. Pure: no files, no network. Raises DecodeError.

    Also imported by email_extract.py, which passes preview=False.
    """
    # Imported late so the caller's limits apply even if a library is slow to load.
    from PIL import Image, UnidentifiedImageError

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        with Image.open(io.BytesIO(data)) as probe:
            kind = FORMATS.get(probe.format or "")
            width, height = probe.size
            if kind is None:
                raise DecodeError("not a PNG, JPEG or WebP image")
            if width > MAX_SIDE or height > MAX_SIDE or width * height > MAX_PIXELS:
                raise DecodeError("image dimensions too large")
            probe.verify()
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            rgb = image.convert("RGB")
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError, SyntaxError):
        raise DecodeError("not a readable image") from None

    import cv2
    import numpy

    pixels = cv2.cvtColor(numpy.asarray(rgb), cv2.COLOR_RGB2BGR)
    # Two detectors, results combined: each misses some codes the other reads (measured:
    # the default one missed a 46-character version 4 code that the Aruco one decoded).
    detectors = [cv2.QRCodeDetectorAruco(), cv2.QRCodeDetector()] if hasattr(cv2, "QRCodeDetectorAruco") else [cv2.QRCodeDetector()]
    payloads: list[str] = []
    for detector in detectors:
        try:
            found, texts, _points, _ = detector.detectAndDecodeMulti(pixels)
            if found:
                payloads.extend(text for text in texts if text)
        except cv2.error:
            pass
    if not payloads:
        try:
            text, _points, _ = cv2.QRCodeDetector().detectAndDecode(pixels)
            if text:
                payloads.append(text)
        except cv2.error:
            pass

    unique = list(dict.fromkeys(payloads))
    result: dict[str, object] = {
        "format": kind,
        "width": width,
        "height": height,
        "codes_found": len(unique),
        "payloads": [text[:MAX_PAYLOAD_CHARS] for text in unique[:MAX_CODES]],
        "truncated": len(unique) > MAX_CODES,
    }
    if preview:
        # A preview drawn here, from decoded pixels, so the host never serves uploaded bytes.
        small = rgb.copy()
        small.thumbnail((PREVIEW_SIDE, PREVIEW_SIDE))
        buffer = io.BytesIO()
        small.save(buffer, format="PNG")
        result["preview_png_b64"] = base64.b64encode(buffer.getvalue()).decode("ascii")
    return result


def main() -> None:
    signal.signal(signal.SIGALRM, on_timeout)
    signal.alarm(TIME_LIMIT_S)

    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        fail("image too large")
    if not data:
        fail("empty upload")
    try:
        result = decode_image(data)
    except DecodeError as exc:
        fail(str(exc))
    reply(ok=True, **result)


if __name__ == "__main__":
    main()
