# ruff: noqa: S603, S606
# Commands are resolved to absolute paths and executed without a shell.
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_NAMESPACE_EXEC = "--namespace-exec"
_HOSTS_ENV = "LMYZMAIL_RBL_HOSTS_FILE"
_RESOLV_CONF_ENV = "LMYZMAIL_RBL_RESOLV_CONF_FILE"
_SOURCE_IP_ENV = "LMYZMAIL_RBL_SOURCE_IP"
_REVERSED_IP_ENV = "LMYZMAIL_RBL_REVERSED_IP"
_RBL_SERVERS = ("listed-one.rbl.test", "absent.rbl.test", "listed-two.rbl.test")
_LISTED_SERVER_INDEXES = (0, 2)
_RESOLV_CONF = "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"


def _required_command(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"required RBL harness command is missing: {name}")
    return str(Path(path).resolve())


def _required_fixture(name: str) -> Path:
    raw = os.environ.get(name)
    if raw is None:
        raise SystemExit(f"required RBL namespace environment is missing: {name}")
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit(f"RBL namespace fixture is not a regular absolute file: {path}")
    return path


def _namespace_exec(arguments: list[str]) -> None:
    if not arguments:
        raise SystemExit("RBL namespace exec command is empty")
    executable = Path(arguments[0])
    if not executable.is_absolute() or not executable.is_file():
        raise SystemExit(f"RBL namespace executable is invalid: {executable}")
    mount = _required_command("mount")
    subprocess.run(
        [mount, "--bind", str(_required_fixture(_HOSTS_ENV)), "/etc/hosts"],
        check=True,
    )
    subprocess.run(
        [
            mount,
            "--bind",
            str(_required_fixture(_RESOLV_CONF_ENV)),
            "/etc/resolv.conf",
        ],
        check=True,
    )
    os.execve(str(executable), arguments, os.environ)


def _discover_source_ipv6() -> ipaddress.IPv6Address:
    completed = subprocess.run(
        [_required_command("ip"), "-j", "-6", "addr", "show", "scope", "global"],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        interfaces: Any = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("ip returned invalid JSON while discovering global IPv6") from error
    candidates: list[tuple[bool, ipaddress.IPv6Address]] = []
    if isinstance(interfaces, list):
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            addresses = interface.get("addr_info")
            if not isinstance(addresses, list):
                continue
            for entry in addresses:
                if not isinstance(entry, dict) or entry.get("family") != "inet6":
                    continue
                raw = entry.get("local")
                flags = entry.get("flags", [])
                if not isinstance(raw, str) or not isinstance(flags, list):
                    continue
                try:
                    address = ipaddress.IPv6Address(raw)
                except ipaddress.AddressValueError:
                    continue
                if not address.is_global or "tentative" in flags or "dadfailed" in flags:
                    continue
                deprecated = bool(entry.get("deprecated")) or "deprecated" in flags
                candidates.append((deprecated, address))
    if not candidates:
        raise SystemExit("RBL harness requires a usable WSL global IPv6 address")
    candidates.sort(key=lambda item: (item[0], int(item[1])))
    return candidates[0][1]


def _reverse_ipv6(address: ipaddress.IPv6Address) -> str:
    return ".".join(reversed(address.exploded.replace(":", "")))


def _listed_query_names(source: ipaddress.IPv6Address) -> tuple[str, ...]:
    reversed_sources = (
        _reverse_ipv6(source),
        "1.0.0.127",
        _reverse_ipv6(ipaddress.IPv6Address("::1")),
        _reverse_ipv6(ipaddress.IPv6Address("::ffff:127.0.0.1")),
    )
    return tuple(
        f"{reversed_source}.{_RBL_SERVERS[index]}"
        for reversed_source in reversed_sources
        for index in _LISTED_SERVER_INDEXES
    )


def _run_pytest(arguments: list[str]) -> int:
    repository = Path(__file__).resolve().parents[2]
    pytest = repository / ".blackbox/venv/bin/pytest"
    if not pytest.is_file() or pytest.is_symlink():
        raise SystemExit(f"native black-box pytest executable is missing: {pytest}")
    source = _discover_source_ipv6()
    environment = dict(os.environ)
    environment[_SOURCE_IP_ENV] = source.compressed
    environment[_REVERSED_IP_ENV] = _reverse_ipv6(source)

    with tempfile.TemporaryDirectory(prefix="lmyzmail-rbl-namespace-") as temporary:
        root = Path(temporary)
        hosts = root / "hosts"
        resolver = root / "resolv.conf"
        hosts.write_text(
            "127.0.0.1 localhost\n"
            "::1 localhost ip6-localhost ip6-loopback\n"
            f"127.0.0.2 {' '.join(_listed_query_names(source))}\n",
            encoding="ascii",
        )
        resolver.write_text(_RESOLV_CONF, encoding="ascii")
        os.chmod(hosts, 0o444)
        os.chmod(resolver, 0o444)
        environment[_HOSTS_ENV] = str(hosts)
        environment[_RESOLV_CONF_ENV] = str(resolver)
        completed = subprocess.run(
            [
                str(pytest),
                "-q",
                "blackbox/tools/test_smtp_content_filter_rbl.py",
                *arguments,
            ],
            cwd=repository,
            env=environment,
            check=False,
        )
        return completed.returncode


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == _NAMESPACE_EXEC:
        _namespace_exec(sys.argv[2:])
        raise AssertionError("namespace exec unexpectedly returned")
    return _run_pytest(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
