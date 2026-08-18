from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


source = Path(__file__).with_name("candidate-soak-v4.py")
spec = importlib.util.spec_from_file_location("candidate_soak_v4", source)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

parser = argparse.ArgumentParser()
parser.add_argument("--duration", type=float, default=1800.0)
parser.add_argument("--workers", type=int, default=16)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
if args.output is not None and args.output.exists():
    raise FileExistsError(f"soak evidence already exists: {args.output}")

result = module.run(args.duration, args.workers)
result["profile"] = "candidate-multi-module-half-hour-soak-v5"
result["runner_source"] = source.relative_to(Path(__file__).resolve().parents[2]).as_posix()
encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
if args.output is not None:
    args.output.write_text(encoded, encoding="utf-8", newline="\n")
print(encoded, end="")
