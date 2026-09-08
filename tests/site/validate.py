#!/usr/bin/env python3
"""Validate the assembled GitHub Pages homepage and canonical report tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
CSS_URL = re.compile(r"url\(\s*(['\"]?)([^)'\"]+)\1\s*\)")
ALLOWED_EXTERNAL_SCHEMES = {"http", "https", "mailto"}
REQUIRED_PATHS = (
    "index.html",
    "styles.css",
    "site.js",
    "reports/latest/index.html",
    "reports/latest/result.json",
    "reports/latest/manifest.sha256",
)


class PageParser(HTMLParser):
    """Collect references and lightweight accessibility metadata."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []
        self.ids: list[str] = []
        self.heading_levels: list[int] = []
        self.anchor_stack: list[dict[str, str]] = []
        self.unnamed_links = 0
        self.has_doctype = False
        self.has_main = False
        self.has_viewport = False
        self.has_base = False
        self.html_lang = ""
        self.title_parts: list[str] = []
        self.in_title = False
        self.images_without_alt = 0
        self.status_is_accessible = False

    def handle_decl(self, decl: str) -> None:
        if decl.lower().strip() == "doctype html":
            self.has_doctype = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()

        for attribute in ("href", "src"):
            if values.get(attribute):
                self.references.append(values[attribute])

        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "html":
            self.html_lang = values.get("lang", "")
        elif tag == "title":
            self.in_title = True
        elif tag == "meta" and values.get("name", "").lower() == "viewport":
            self.has_viewport = bool(values.get("content"))
        elif tag == "main":
            self.has_main = True
        elif tag == "base":
            self.has_base = True
        elif tag == "img" and "alt" not in values:
            self.images_without_alt += 1
        elif tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.heading_levels.append(int(tag[1]))
        elif tag == "a":
            self.anchor_stack.append({"text": "", "aria": values.get("aria-label", "")})

        if values.get("id") == "report-status" and (
            values.get("role") == "status" or values.get("aria-live") in {"polite", "assertive"}
        ):
            self.status_is_accessible = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag == "a" and self.anchor_stack:
            anchor = self.anchor_stack.pop()
            if not anchor["text"].strip() and not anchor["aria"].strip():
                self.unnamed_links += 1

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        for anchor in self.anchor_stack:
            anchor["text"] += data


def parse_page(path: Path) -> PageParser:
    parser = PageParser()
    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()
    return parser


def ensure_safe_tree(root: Path, errors: list[str]) -> None:
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            errors.append(f"{relative}: symbolic links are not allowed")
        elif path.is_file() and path.stat().st_nlink != 1:
            errors.append(f"{relative}: hard-linked files are not allowed")


def validate_manifest(root: Path, errors: list[str]) -> None:
    report_root = root / "reports" / "latest"
    manifest_path = report_root / "manifest.sha256"
    if not manifest_path.is_file():
        return

    recorded: dict[str, str] = {}
    for number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        match = MANIFEST_LINE.fullmatch(line)
        if not match:
            errors.append(f"reports/latest/manifest.sha256:{number}: malformed entry")
            continue
        digest, relative = match.groups()
        posix = PurePosixPath(relative)
        if posix.is_absolute() or ".." in posix.parts or posix.as_posix() != relative:
            errors.append(f"reports/latest/manifest.sha256:{number}: unsafe path {relative!r}")
            continue
        if relative in recorded:
            errors.append(f"reports/latest/manifest.sha256:{number}: duplicate path {relative!r}")
            continue
        recorded[relative] = digest

    actual = {
        relative
        for path in report_root.rglob("*")
        if path.is_file() and (relative := path.relative_to(report_root).as_posix()) != "manifest.sha256"
    }
    missing = sorted(actual - recorded.keys())
    extra = sorted(recorded.keys() - actual)
    if missing:
        errors.append(f"report manifest is missing files: {', '.join(missing)}")
    if extra:
        errors.append(f"report manifest names absent files: {', '.join(extra)}")

    for relative, expected in recorded.items():
        path = report_root / relative
        if not path.is_file():
            continue
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_digest != expected:
            errors.append(f"reports/latest/{relative}: SHA-256 does not match manifest")


def local_target(root: Path, source: Path, reference: str, errors: list[str]) -> tuple[Path, str] | None:
    parsed = urlsplit(reference)
    if reference.startswith("//"):
        errors.append(f"{source.relative_to(root)}: protocol-relative URL is not allowed: {reference!r}")
        return None
    if parsed.scheme:
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_EXTERNAL_SCHEMES:
            errors.append(f"{source.relative_to(root)}: URL scheme is not allowed: {reference!r}")
        elif scheme in {"http", "https"} and not parsed.netloc:
            errors.append(f"{source.relative_to(root)}: external URL has no host: {reference!r}")
        elif scheme == "mailto" and not parsed.path:
            errors.append(f"{source.relative_to(root)}: mailto URL has no address: {reference!r}")
        return None
    if parsed.netloc:
        errors.append(f"{source.relative_to(root)}: URL authority requires an allowed scheme: {reference!r}")
        return None
    if parsed.path.startswith("/"):
        errors.append(f"{source.relative_to(root)}: root-relative URL breaks project Pages: {reference!r}")
        return None

    decoded = unquote(parsed.path)
    target = source if not decoded else source.parent / decoded
    resolved_root = root.resolve()
    resolved = target.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        errors.append(f"{source.relative_to(root)}: URL escapes the Pages tree: {reference!r}")
        return None
    if resolved.is_dir():
        resolved = resolved / "index.html"
    return resolved, unquote(parsed.fragment)


def validate_references(root: Path, pages: dict[Path, PageParser], errors: list[str]) -> None:
    references: list[tuple[Path, str]] = []
    for path, parser in pages.items():
        references.extend((path, reference) for reference in parser.references)
        if parser.has_base:
            errors.append(f"{path.relative_to(root)}: <base> is not allowed on a project Pages site")

    for stylesheet in root.rglob("*.css"):
        text = stylesheet.read_text(encoding="utf-8")
        references.extend((stylesheet, match.group(2).strip()) for match in CSS_URL.finditer(text))

    for source, reference in references:
        target_info = local_target(root, source, reference, errors)
        if target_info is None:
            continue
        target, fragment = target_info
        if not target.is_file():
            errors.append(f"{source.relative_to(root)}: missing local target for {reference!r}")
            continue
        if fragment and target.suffix.lower() in {".html", ".htm"}:
            target_parser = pages.get(target)
            if target_parser is None:
                target_parser = parse_page(target)
                pages[target] = target_parser
            if fragment not in target_parser.ids:
                errors.append(
                    f"{source.relative_to(root)}: fragment #{fragment} is absent from {target.relative_to(root)}"
                )


def validate_homepage(root: Path, parser: PageParser, errors: list[str]) -> None:
    if not parser.has_doctype:
        errors.append("index.html: missing HTML5 doctype")
    if not parser.html_lang.strip():
        errors.append("index.html: html element must declare a language")
    if not "".join(parser.title_parts).strip():
        errors.append("index.html: title must not be empty")
    if not parser.has_viewport:
        errors.append("index.html: viewport metadata is required")
    if not parser.has_main:
        errors.append("index.html: main landmark is required")
    if parser.heading_levels.count(1) != 1:
        errors.append("index.html: exactly one h1 is required")
    for previous, current in zip(parser.heading_levels, parser.heading_levels[1:]):
        if current > previous + 1:
            errors.append(f"index.html: heading level jumps from h{previous} to h{current}")
    duplicates = sorted({identifier for identifier in parser.ids if parser.ids.count(identifier) > 1})
    if duplicates:
        errors.append(f"index.html: duplicate ids: {', '.join(duplicates)}")
    if parser.images_without_alt:
        errors.append("index.html: every image must have an alt attribute")
    if parser.unnamed_links:
        errors.append("index.html: every link must have accessible text or an aria-label")
    if not parser.status_is_accessible:
        errors.append("index.html: report status must use role=status or aria-live")
    if not any(urlsplit(reference).path in {"reports/latest/", "./reports/latest/"} for reference in parser.references):
        errors.append("index.html: direct reports/latest/ link is required")


def validate_result(root: Path, errors: list[str]) -> None:
    path = root / "reports" / "latest" / "result.json"
    if not path.is_file():
        return
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"reports/latest/result.json: cannot parse JSON: {exc}")
        return
    if not isinstance(result, dict) or result.get("suite") != "kaiba-dns-pilot":
        errors.append("reports/latest/result.json: unexpected suite")
        return
    assertions = result.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        errors.append("reports/latest/result.json: assertions must be a non-empty list")
        return
    statuses = [item.get("status") if isinstance(item, dict) else None for item in assertions]
    if any(status not in {"passed", "failed"} for status in statuses):
        errors.append("reports/latest/result.json: malformed assertion status")
        return
    expected = "passed" if all(status == "passed" for status in statuses) else "failed"
    if result.get("overall") != expected:
        errors.append(f"reports/latest/result.json: overall must be {expected!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="assembled GitHub Pages tree")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    errors: list[str] = []

    if not root.is_dir():
        parser.error(f"not a directory: {root}")
    for relative in REQUIRED_PATHS:
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")

    ensure_safe_tree(root, errors)
    validate_manifest(root, errors)
    pages = {path.resolve(): parse_page(path) for path in root.rglob("*.html")}
    homepage = pages.get((root / "index.html").resolve())
    if homepage is not None:
        validate_homepage(root, homepage, errors)
    validate_references(root, pages, errors)
    validate_result(root, errors)

    if errors:
        for error in errors:
            print(f"site validation: {error}", file=sys.stderr)
        return 1
    file_count = sum(1 for path in root.rglob("*") if path.is_file())
    print(f"validated Pages site with {file_count} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
