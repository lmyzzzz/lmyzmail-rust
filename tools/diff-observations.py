#!/usr/bin/env python3
"""Print exact structural differences; never normalize or change either input."""
import json
import sys
from pathlib import Path


def differences(expected, actual, path="$"):
    if type(expected) is not type(actual):
        print(json.dumps({"path": path, "expected": expected, "actual": actual}, ensure_ascii=False))
    elif isinstance(expected, dict):
        for key in sorted(expected.keys() | actual.keys()):
            if key not in expected or key not in actual:
                print(json.dumps({"path": path + "/" + key, "expected": expected.get(key),
                                  "actual": actual.get(key), "missing_key": True}, ensure_ascii=False))
            else:
                differences(expected[key], actual[key], path + "/" + key)
    elif isinstance(expected, list) and len(expected) == len(actual):
        for index, (left, right) in enumerate(zip(expected, actual, strict=True)):
            differences(left, right, f"{path}/{index}")
    elif expected != actual:
        print(json.dumps({"path": path, "expected": expected, "actual": actual}, ensure_ascii=False))


if __name__ == "__main__":
    expected = json.loads(Path(sys.argv[1]).read_text())
    actual = json.loads(Path(sys.argv[2]).read_text())
    differences(expected.get("observation", expected), actual.get("observation", actual))
