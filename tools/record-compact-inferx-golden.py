#!/usr/bin/env python3
"""Create a new-model golden using only the hash-pinned frozen Java oracle.

The original model's golden is never changed. Java is a test dependency only.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODEL_HASH = "4fc4f7a0eb5d7e1210ddd7fee63a756775f5b7155db210080cfd8cc759403428"
TOKENIZER_HASH = "6624adb41b9274bf0cc73c62ebd26eb2bcf281d533f30607ba415105917d81f3"
JAR_HASH = "fe2d8fcefad9a4127398eeb5d911805ea10a8dce75ec70912fd3be909c8fbdfc"
PROBE_HASH = "bc671c51a41494327494268c4c299367992bbe084b73e00688b5d9db0e48a683"


def verify(path: Path, expected: str) -> None:
    with path.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise RuntimeError(f"hash mismatch: {path}: {actual} != {expected}")


def main() -> None:
    jar = ROOT / "oracle/artifacts/lmyzmail-java-oracle.jar"
    probe = ROOT / "blackbox/tools/InferxOracleProbe.java"
    model = ROOT / "models/skibidi-inferx-compact-20261022/skibidi_ai.safetensors"
    tokenizer = ROOT / "models/skibidi-inferx-compact-20261022/tokenizer.json"
    jdk = ROOT / ".blackbox/runtime/jdk22/bin"
    for path, expected in ((jar, JAR_HASH), (probe, PROBE_HASH),
                           (model, MODEL_HASH), (tokenizer, TOKENIZER_HASH)):
        verify(path, expected)
    output = ROOT / "blackbox/golden/native/skibidi-inferx-compact-20261022/contract.json"
    if output.exists():
        raise FileExistsError(f"golden is create-once: {output}")
    with tempfile.TemporaryDirectory(prefix="inferx-compact-", dir=ROOT / ".blackbox") as tmp:
        work = Path(tmp)
        with zipfile.ZipFile(jar) as archive:
            names = [name for name in archive.namelist() if (
                name.startswith("BOOT-INF/classes/net/lmyz/lmyzmail/skibidi_inferx/")
                and name.endswith(".class")
            ) or name in (
                "BOOT-INF/classes/native/linux-x86_64/libskibidi_inferx_native.so",
                "BOOT-INF/lib/slf4j-api-2.0.17.jar",
            )]
            for name in names:
                if not (work / name).resolve().is_relative_to(work):
                    raise ValueError(f"invalid oracle archive path: {name}")
                archive.extract(name, work)
        classes = work / "BOOT-INF/classes"
        classpath = os.pathsep.join((str(classes), str(work / "BOOT-INF/lib/slf4j-api-2.0.17.jar")))
        subprocess.run([str(jdk / "javac"), "-encoding", "UTF-8", "-cp", classpath,
                        "-d", str(classes), str(probe)], check=True, timeout=60)
        results = []
        for backend in (0, 1):
            for _ in range(2):
                run = subprocess.run([
                    str(jdk / "java"), "-cp", classpath,
                    "net.lmyz.lmyzmail.skibidi_inferx.InferxOracleProbe",
                    str(model), str(tokenizer), str(backend),
                ], check=True, capture_output=True, text=True, timeout=120)
                result = json.loads(run.stdout)
                expected_backend = ("Scalar", "AVX2+FMA")[backend]
                if result.pop("simd") != expected_backend:
                    raise RuntimeError(f"requested {expected_backend} did not execute")
                results.append(result)
        if any(result != results[0] for result in results[1:]):
            raise AssertionError("repeat/backend mismatch; refusing to admit golden")
        document = {
            "schema_version": 1,
            "profile": "skibidi-inferx-compact-20261022",
            "oracle": {
                "commit": "5dac2ab2922c30c726c4a83d7626c95ad4e231c8",
                "jar_sha256": JAR_HASH,
                "probe_sha256": PROBE_HASH,
                "verified_backends": ["Scalar", "AVX2+FMA"],
                "independent_processes_per_backend": 2,
            },
            **results[0],
        }
        document["model"].update(safetensors_sha256=MODEL_HASH, tokenizer_sha256=TOKENIZER_HASH)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as destination:
            json.dump(document, destination, indent=2, ensure_ascii=False)
            destination.write("\n")
        print(output)


if __name__ == "__main__":
    main()
