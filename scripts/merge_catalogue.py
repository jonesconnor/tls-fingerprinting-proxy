"""
merge_catalogue.py — Merge .capture-tmp/*.json entries into the catalogue.

Reads every *.json file from .capture-tmp/, validates each against the schema,
then atomically writes the merged result to catalogue/ai-sdk-fingerprints.json.

Merge rules:
  - New entries (ja4 not yet in the catalogue) are appended.
  - Duplicate ja4 hashes: warn and skip (don't silently overwrite existing data).
  - Existing catalogue entries not present in .capture-tmp/ are preserved.
  - Final write uses os.replace() for atomicity (no partial JSON on SIGKILL).

Usage
-----
  python3 scripts/merge_catalogue.py
  python3 scripts/merge_catalogue.py --tmp-dir .capture-tmp --catalogue catalogue/ai-sdk-fingerprints.json

Makefile integration
--------------------
  make merge-catalogue
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT    = Path(__file__).resolve().parent.parent
CAPTURE_TMP_DIR = PROJECT_ROOT / ".capture-tmp"
CATALOGUE_PATH  = PROJECT_ROOT / "catalogue" / "ai-sdk-fingerprints.json"
SCHEMA_PATH     = PROJECT_ROOT / "catalogue" / "schema.json"


def load_schema(schema_path: Path = SCHEMA_PATH) -> dict:
    with open(schema_path) as f:
        return json.load(f)


def validate_entry(entry: dict, schema: dict) -> None:
    """Validate entry against schema. Raises jsonschema.ValidationError on failure."""
    try:
        import jsonschema
    except ImportError:
        raise ImportError("jsonschema is required: pip install jsonschema")
    jsonschema.validate(entry, schema)


def load_existing_catalogue(catalogue_path: Path) -> list[dict]:
    """Load existing catalogue entries. Returns empty list if file is missing or empty."""
    if not catalogue_path.exists():
        return []
    text = catalogue_path.read_text().strip()
    if not text:
        return []
    return json.loads(text)


def merge_catalogue(
    tmp_dir: Path = CAPTURE_TMP_DIR,
    catalogue_path: Path = CATALOGUE_PATH,
    schema_path: Path = SCHEMA_PATH,
) -> list[dict]:
    """
    Core merge logic. Returns the final list of entries after writing atomically.

    1. Load existing catalogue (keyed by ja4).
    2. Load and validate each *.json in tmp_dir.
    3. Add new entries; warn + skip duplicates.
    4. Write full merged array atomically via os.replace().
    """
    schema = load_schema(schema_path)

    # Load existing entries, keyed by ja4 for O(1) duplicate detection
    existing = load_existing_catalogue(catalogue_path)
    by_ja4: dict[str, dict] = {e["ja4"]: e for e in existing}

    tmp_files = sorted(tmp_dir.glob("*.json"))
    if not tmp_files:
        print(f"No entries found in {tmp_dir.relative_to(PROJECT_ROOT)}/")
        print("Run 'make capture-sdk SDK=...' first.")
        return existing

    added   = 0
    skipped = 0

    for tmp_file in tmp_files:
        try:
            entry = json.loads(tmp_file.read_text())
        except json.JSONDecodeError as exc:
            print(f"  WARNING: skipping {tmp_file.name} (invalid JSON: {exc})")
            skipped += 1
            continue

        try:
            validate_entry(entry, schema)
        except Exception as exc:
            print(f"  WARNING: skipping {tmp_file.name} (schema error: {exc})")
            skipped += 1
            continue

        ja4 = entry["ja4"]
        if ja4 in by_ja4:
            existing_sdk = by_ja4[ja4]["sdk"]
            print(
                f"  WARNING: duplicate JA4 {ja4} "
                f"({entry['sdk']} vs existing {existing_sdk}) — skipping"
            )
            skipped += 1
        else:
            by_ja4[ja4] = entry
            added += 1
            print(f"  + {entry['sdk']} ({entry['os']})  {ja4}")

    merged = sorted(by_ja4.values(), key=lambda e: (e["sdk"], e.get("os", "")))

    # Atomic write: write to a temp file, then rename into place
    tmp_out = catalogue_path.with_suffix(".tmp")
    tmp_out.write_text(json.dumps(merged, indent=2) + "\n")
    os.replace(str(tmp_out), str(catalogue_path))

    print(f"\nCatalogue updated: {added} added, {skipped} skipped, {len(merged)} total entries.")
    print(f"Written to: {os.path.relpath(catalogue_path, PROJECT_ROOT)}")

    return merged


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge .capture-tmp/*.json entries into the AI SDK fingerprint catalogue."
    )
    parser.add_argument(
        "--tmp-dir",
        type=Path,
        default=CAPTURE_TMP_DIR,
        help=f"Directory of captured .json files (default: {CAPTURE_TMP_DIR.relative_to(PROJECT_ROOT)})",
    )
    parser.add_argument(
        "--catalogue",
        type=Path,
        default=CATALOGUE_PATH,
        help=f"Catalogue file to merge into (default: {CATALOGUE_PATH.relative_to(PROJECT_ROOT)})",
    )
    args = parser.parse_args()
    merge_catalogue(tmp_dir=args.tmp_dir, catalogue_path=args.catalogue)


if __name__ == "__main__":
    main()
