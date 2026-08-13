#!/usr/bin/env python3
"""Bind a validated provisioning platform result to one source revision."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

import render


MAX_INPUT_BYTES = 64 * 1024


def write_new(path: Path, content: str) -> None:
    if not path.parent.is_dir():
        raise OSError(f"output parent is not a directory: {path.parent}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o644)
        os.link(temporary_name, path)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def create_receipt(input_path: Path, source_revision: str, output_path: Path) -> None:
    try:
        input_size = input_path.stat().st_size
    except OSError as exc:
        raise render.ReportError(f"platform result: cannot inspect input: {exc}") from exc
    if input_size > MAX_INPUT_BYTES:
        raise render.ReportError(
            f"platform result: input exceeds {MAX_INPUT_BYTES} bytes"
        )
    if not render.SOURCE_REVISION.fullmatch(source_revision):
        raise render.ReportError(
            "source revision: must be a lowercase 40- or 64-hex value"
        )

    raw = render.normalize_and_scan(
        render.load_json(input_path, "provisioning platform result"),
        "provisioning_platform_result",
    )
    receipt = render.validate_platform_result(
        raw,
        None,
        require_source_revision=False,
    )
    existing_revision = receipt.get("source_revision")
    if existing_revision not in {None, source_revision}:
        raise render.ReportError(
            "provisioning platform result.source_revision: refuses to replace a different revision"
        )
    receipt["source_revision"] = source_revision
    receipt["checks"].sort(key=lambda item: item["id"])
    render.validate_platform_result(receipt, None, require_source_revision=True)
    write_new(output_path, render.json_text(receipt))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="unstamped Nix platform result")
    parser.add_argument("--source-revision", required=True, help="checked-out 40- or 64-hex revision")
    parser.add_argument("--output", type=Path, required=True, help="new receipt path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        create_receipt(args.input, args.source_revision, args.output)
    except render.ReportError as exc:
        print(f"platform receipt error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"platform receipt error: cannot write output: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
