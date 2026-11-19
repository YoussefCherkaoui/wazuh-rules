#!/usr/bin/env python3
"""Controlla il ruleset: XML ben formato, ID unici e nell'intervallo giusto."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CUSTOM_MIN, CUSTOM_MAX = 100000, 120000
EXAMPLE_MAX = 100099


def parse(path: Path) -> ET.Element:
    # I file Wazuh hanno piu' elementi radice: li avvolgo in un unico nodo.
    text = path.read_text(encoding="utf-8")
    return ET.fromstring(f"<root>{text}</root>")


def main() -> int:
    errors: list[str] = []
    seen: dict[int, Path] = {}
    files = sorted(
        p
        for folder in ("rules", "decoders", "examples")
        for p in (ROOT / folder).glob("*.xml")
    )

    for path in files:
        rel = path.relative_to(ROOT)
        try:
            tree = parse(path)
        except ET.ParseError as exc:
            errors.append(f"{rel}: XML non valido ({exc})")
            continue

        for rule in tree.iter("rule"):
            raw = rule.get("id", "")
            if not raw.isdigit():
                errors.append(f"{rel}: regola senza id numerico")
                continue
            rid = int(raw)
            in_examples = rel.parts[0] == "examples"
            low = CUSTOM_MIN if in_examples else EXAMPLE_MAX + 1
            high = EXAMPLE_MAX if in_examples else CUSTOM_MAX
            if not low <= rid <= high:
                errors.append(f"{rel}: id {rid} fuori dall'intervallo {low}-{high}")
            if rid in seen:
                errors.append(f"{rel}: id {rid} gia' usato in {seen[rid].relative_to(ROOT)}")
            seen[rid] = path

    for err in errors:
        print(f"ERRORE  {err}")
    print(f"{len(files)} file controllati, {len(seen)} regole, {len(errors)} errori")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
