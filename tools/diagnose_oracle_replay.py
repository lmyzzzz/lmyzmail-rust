"""Read-only protocol observations for the two retained oracle replay failures.

Does not record golden files, patch the oracle, or change contract assertions.
All services and data are isolated by the existing managed runtimes.
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import shutil
import sys
import time
from pathlib import Path

import psycopg
import pytest
import redis

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "blackbox/tests"))
sys.path.insert(0, str(ROOT / "blackbox/tools"))
from lmyzmail_blackbox.scripted_dns import ScriptedDnsServer  # noqa: E402


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def preserve_logs(runtime, output: Path) -> None:
    if runtime.workspace is None:
        return
    for source in runtime.workspace.glob("*.log"):
        shutil.copyfile(source, output / source.name)


def dmarc(output: Path, *, debug: bool = False, verify: bool = False,
          local_hosts: bool = False) -> dict:
    module = load("diagnostic_dmarc", ROOT / "blackbox/tests/test_oracle_smtp_dmarc.py")
    events = []
    started = time.monotonic()

    class TimedDns(ScriptedDnsServer):
        def _response(self, packet):
            response = super()._response(packet)
            events.append({"elapsed_seconds": time.monotonic() - started,
                           **dataclasses.asdict(self.queries()[-1])})
            return response

    class Runtime(module._DmarcJavaRuntime):
        def _application_arguments(self):
            arguments = super()._application_arguments()
            if local_hosts:
                hosts = output.absolute() / "java-hosts"
                hosts.write_text("127.0.0.1 localhost\n", encoding="ascii")
                arguments.insert(arguments.index("-jar"), f"-Djdk.net.hosts.file={hosts}")
            if not debug:
                return arguments
            return [*arguments,
                    "--logging.level.net.lmyz.lmyzmail.inbound=DEBUG",
                    "--logging.level.org.xbill.DNS=DEBUG"]

        def stop(self):
            preserve_logs(self, output)
            super().stop()

    module.ScriptedDnsServer = TimedDns
    result = {"cases": [], "dns_events": events}
    if verify:
        class Plugin:
            def pytest_collection_modifyitems(self, items):
                for item in items:
                    item.module.ScriptedDnsServer = TimedDns
                    item.module._DmarcJavaRuntime = Runtime

        result["pytest_exitstatus"] = int(pytest.main([
            "-c", str(ROOT / "blackbox/pyproject.toml"), "-p", "release_campaign",
            "blackbox/tests/test_oracle_smtp_dmarc.py::test_managed_java_smtp_dmarc_golden",
            "-q", f"--junitxml={output / 'replay.xml'}",
        ], plugins=[Plugin()]))
        return result
    runtime = Runtime()
    try:
        runtime.start()
        for scenario in module.SMTP_DMARC_SCENARIOS:
            try:
                observation = scenario.capture(runtime)
                result["cases"].append({"scenario": scenario.name, "observation": observation})
            except Exception as error:
                result["cases"].append({"scenario": str(scenario), "error": repr(error)})
                break
    finally:
        preserve_logs(runtime, output)
        runtime.stop()
    return result


def multi_domain(output: Path, *, delayed: bool = False) -> dict:
    module = load("diagnostic_multi_domain", ROOT / "blackbox/tools/test_java_multi_domain.py")
    runtime = module._MultiDomainStressJavaRuntime(output / "runtime")
    result = {"samples": []}
    try:
        runtime.start()
        target = module._Target(runtime)
        result["surface"] = module._capture(target)
        if delayed:
            # Intentionally miss the initial scheduler tick to distinguish
            # Redis admission from the later Write-Behind archive lifecycle.
            time.sleep(6)
        started = time.monotonic()
        try:
            result["stress"] = module._capture_stress_multi_domain(target)
        except Exception as error:
            result["original_contract_error"] = repr(error)
        assert runtime.ports is not None
        cache = redis.Redis(host="127.0.0.1", port=runtime.ports.redis, decode_responses=True)
        with psycopg.connect(host="127.0.0.1", port=runtime.ports.postgres,
                             dbname="lmyzmail", user="lmyzmail_test", autocommit=True) as db:
            while time.monotonic() - started < 80:
                keys = sorted(cache.scan_iter(match="botmail:mail:queue:*", count=100))
                values = {}
                for key in keys:
                    kind = cache.type(key)
                    if kind == "string":
                        value = cache.get(key)
                    elif kind == "hash":
                        value = cache.hgetall(key)
                    elif kind == "list":
                        value = cache.lrange(key, 0, 10)
                    elif kind == "zset":
                        value = cache.zrange(key, 0, 10, withscores=True)
                    else:
                        value = kind
                    values[key] = value
                rows = db.execute("SELECT id,sender_address,recipients_json,status FROM "
                                  "outbound_mail_queue ORDER BY id").fetchall()
                result["samples"].append({"elapsed_seconds": time.monotonic() - started,
                                          "redis": values, "postgres": rows})
                if any(str(row[1]).startswith("multi-stress-sender@") for row in rows):
                    break
                time.sleep(1)
    finally:
        preserve_logs(runtime, output)
        runtime.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=("dmarc", "multi-domain"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--delayed", action="store_true")
    parser.add_argument("--local-hosts", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        result = (dmarc(args.output, debug=args.debug, verify=args.verify,
                        local_hosts=args.local_hosts)
                  if args.case == "dmarc" else multi_domain(args.output, delayed=args.delayed))
    except Exception as error:
        result = {"diagnostic_error": repr(error)}
        raise
    finally:
        if "result" in locals():
            (args.output / "observations.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
