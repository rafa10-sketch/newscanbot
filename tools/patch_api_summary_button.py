#!/usr/bin/env python3
"""Patch dashboard scan page to download summarized API evidence for API scans."""

from pathlib import Path


TARGET = Path.home() / "newbotdashboard/frontend/app/scan/[id]/page.tsx"


def replace_once(text: str, old: str, new: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise SystemExit(f"Pattern not found in {TARGET}:\n{old}")
    return text.replace(old, new, 1)


def main() -> None:
    if not TARGET.exists():
        raise SystemExit(f"File not found: {TARGET}")

    text = TARGET.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "  downloadReport,\n  downloadRawData,\n  cancelScan,",
        "  downloadReport,\n  downloadRawData,\n  downloadApiEvidence,\n  cancelScan,",
    )

    text = replace_once(
        text,
        '            onClick={() => downloadRawData(scanId).catch((e) => alert(e.message))}',
        '            onClick={() => (\n'
        '              scan.scanMode === "api" ? downloadApiEvidence(scanId) : downloadRawData(scanId)\n'
        '            ).catch((e) => alert(e.message))}',
    )

    text = replace_once(
        text,
        '{scan.scanMode === "api" ? "📊 Download API Evidence JSON" : "📊 Download Raw JSON"}',
        '{scan.scanMode === "api" ? "📊 Download API Summary JSON" : "📊 Download Raw JSON"}',
    )

    if "Download API Summary JSON" not in text:
        text = replace_once(
            text,
            "📊 Download Raw JSON",
            '{scan.scanMode === "api" ? "📊 Download API Summary JSON" : "📊 Download Raw JSON"}',
        )

    TARGET.write_text(text, encoding="utf-8")
    print(f"Patched {TARGET}")


if __name__ == "__main__":
    main()
