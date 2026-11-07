#!/usr/bin/env python3
"""Fail if published text files contain contact or location details.

Patterns are generic. This file stores no real personal data. Matches are
reported as category and line number only.
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "node_modules"}
TEXT_SUFFIXES = {
    ".html",
    ".htm",
    ".js",
    ".mjs",
    ".css",
    ".json",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".svg",
    ".xml",
    ".csv",
    ".py",
}

AT = "@"
MAIL = "mail" + "to:"
TEL = "te" + "l:"
GEO_LAT = "lati" + "tude"
GEO_LON = "longi" + "tude"
ENC_AT = "%" + "40"

EMAIL = re.compile(
    r"(?i)(?<![\w.+-])[a-z0-9._%+-]{1,64}"
    + AT
    + r"[a-z0-9.-]+\.[a-z]{2,}"
)
ENCODED_EMAIL = re.compile(
    r"(?i)(?<![\w.+-])[a-z0-9._%+-]{1,64}(?:"
    + ENC_AT
    + r"|&#0*64;|&commat;)[a-z0-9.-]+\.[a-z]{2,}"
)
MAILTO = re.compile(re.escape(MAIL), re.I)
TEL_URI = re.compile(r"(?i)(?<![a-z])" + TEL)
PHONE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}(?!\d)"
)
STREET = re.compile(
    r"(?i)\b\d{1,6}\s+(?:[A-Za-z0-9.'-]+\s+){1,5}"
    r"(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|boulevard|blvd|"
    r"court|ct|way|place|pl|terrace|ter|circle|cir|trail|trl)\b\.?"
)
GPS = re.compile(
    rf"(?i)\b(?:{GEO_LAT}|{GEO_LON})\b|"
    r"[+-]?\d{1,2}\.\d{5,}\s*,\s*[+-]?\d{1,3}\.\d{5,}"
)
ZIP4 = re.compile(r"\b\d{5}-\d{4}\b")
PAYMENT_MAILBOX = re.compile(
    r"(?i)(?:business|email|phone)=[^&\s\"']*(?:" + AT + "|" + ENC_AT + ")"
)


def decode(value: str) -> str:
    current = value
    for _ in range(3):
        nxt = html.unescape(unquote(current))
        if nxt == current:
            return current
        current = nxt
    return current


def categories_for_line(line: str) -> list[str]:
    decoded = decode(line)
    found: list[str] = []
    checks = (
        ("email", EMAIL, decoded),
        ("encoded-email", ENCODED_EMAIL, line),
        ("mailto", MAILTO, decoded),
        ("telephone-link", TEL_URI, decoded),
        ("phone", PHONE, decoded),
        ("street-address", STREET, decoded),
        ("coordinates", GPS, decoded),
        ("zip-plus-4", ZIP4, decoded),
        ("payment-mailbox", PAYMENT_MAILBOX, line),
    )
    for name, pattern, blob in checks:
        if pattern.search(blob):
            found.append(name)
    return found


def iter_text_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        files.append(path)
    return sorted(files)


def scan_files(paths: list[Path]) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for path in paths:
        raw = path.read_bytes()
        if b"\0" in raw[:4096]:
            continue
        text = raw.decode("utf-8", "replace")
        rel = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(text.splitlines(), 1):
            for category in categories_for_line(line):
                findings.append((rel, number, category))
    return findings


def self_test() -> list[str]:
    samples = {
        "email": "note " + "privacy-check" + AT + "example.com",
        "encoded-email": "business=privacy-check" + ENC_AT + "example.com",
        "mailto": "see " + MAIL + "privacy-check" + AT + "example.com",
        "telephone-link": "href='" + TEL + "5550100199'",
        "phone": "call " + "555" + "-010-" + "0199",
        "street-address": "123 Example " + "Lane",
        "coordinates": GEO_LAT + " 40.12345",
        "zip-plus-4": "code " + "00000" + "-0000",
        "payment-mailbox": "business=privacy-check" + ENC_AT + "example.com",
    }
    errors: list[str] = []
    for expected, sample in samples.items():
        got = categories_for_line(sample)
        if expected not in got:
            errors.append(expected)
    clean = categories_for_line("ForeverIRL character sheet with rarity colors")
    if clean:
        errors.append("clean-line:" + ",".join(clean))
    return errors


def main() -> int:
    errors = self_test()
    if errors:
        print("privacy guard self-test failed:", ", ".join(errors), file=sys.stderr)
        return 2
    findings = scan_files(iter_text_files())
    if findings:
        print("privacy guard found contact or location details:")
        for rel, number, category in findings:
            print(f"  {rel}:{number} {category}")
        return 1
    print("privacy guard: no contact or location details in published text")
    return 0


if __name__ == "__main__":
    sys.exit(main())
