#!/usr/bin/env python3
"""Prova le condizioni <field> delle regole sugli eventi in tests/*.json.

Controlla solo i campi della singola regola (non la catena di if_sid e non
il decoder): serve a verificare che le regex scattino sui casi giusti.
Le regex pcre2 vengono valutate con il modulo re di Python, che copre la
sintassi usata qui. La prova definitiva resta wazuh-logtest sul manager.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_rules(path: Path) -> dict[str, list[tuple[str, str]]]:
    tree = ET.fromstring(f"<root>{path.read_text(encoding='utf-8')}</root>")
    return {
        rule.get("id"): [(f.get("name"), f.text or "") for f in rule.findall("field")]
        for rule in tree.iter("rule")
    }


def flatten(data: dict, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in data.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, f"{name}."))
        else:
            out[name] = str(value)
    return out


def matches(fields: list[tuple[str, str]], event: dict[str, str]) -> bool:
    return all(re.search(pattern, event.get(name, "")) for name, pattern in fields)


def main() -> int:
    failures = 0
    total = 0
    for spec_path in sorted((ROOT / "tests").glob("*.json")):
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        rules = load_rules(ROOT / spec["rules"])
        for case in spec["cases"]:
            event = flatten(json.loads((ROOT / case["event"]).read_text(encoding="utf-8")))
            event.update(case.get("override", {}))
            for rule_id, expected in case["expect"].items():
                total += 1
                got = matches(rules[rule_id], event)
                status = "ok    " if got == expected else "ERRORE"
                if got != expected:
                    failures += 1
                print(f"{status}  {rule_id}  {case['name']} (atteso {expected}, ottenuto {got})")
    print(f"{total} verifiche, {failures} errori")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
