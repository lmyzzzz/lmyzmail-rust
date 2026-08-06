from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

import httpx

from .errors import HarnessError, ProcessStartError, ProtocolError
from .ports import PortAllocator, PortSet
from .processes import ManagedProcess, stop_managed_processes
from .protocols import connect_bounded, read_smtp_reply
from .tls_fixture import EphemeralTlsMaterial, provision_ephemeral_tls_material

QA_ADDRESS = "qa@example.test"
# Public, isolated fixture credential specified by the compatibility contract.
QA_PASSWORD = "BlackboxPass123!"  # noqa: S105
API_KEY = "blackbox-admin-key"
READ_ONLY_API_KEY = "blackbox-read-key"
WRITE_ONLY_API_KEY = "blackbox-write-key"


@dataclass(frozen=True, slots=True)
class HarnessPaths:
    repository: Path
    runtime: Path
    oracle_jar: Path
    java_manifest: Path

    @classmethod
    def discover(cls) -> HarnessPaths:
        repository = Path(__file__).resolve().parents[3]
        return cls(
            repository=repository,
            runtime=repository / ".blackbox" / "runtime",
            oracle_jar=repository / "oracle" / "artifacts" / "lmyzmail-java-oracle.jar",
            java_manifest=(repository / "evidence" / "freeze" / "java-oracle" / "baseline.json"),
        )


@dataclass(slots=True)
class JavaOracleRuntime:
    paths: HarnessPaths = field(default_factory=HarnessPaths.discover)
    startup_timeout: float = 90.0
    shutdown_timeout: float = 5.0
    shutdown_kill_timeout: float = 2.0
    ports: PortSet | None = field(default=None, init=False)
    workspace: Path | None = field(default=None, init=False)
    _temporary: tempfile.TemporaryDirectory[str] | None = field(
        default=None, init=False, repr=False
    )
    _port_allocator: PortAllocator | None = field(default=None, init=False, repr=False)
    _application_ports_released: bool = field(default=False, init=False, repr=False)
    _postgres: ManagedProcess | None = field(default=None, init=False, repr=False)
    _redis: ManagedProcess | None = field(default=None, init=False, repr=False)
    _application: ManagedProcess | None = field(default=None, init=False, repr=False)

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    def _verify_backend_inputs(self) -> None:
        required = (
            self.paths.runtime / "postgres-root" / "usr/lib/postgresql/16/bin/initdb",
            self.paths.runtime / "redis-root" / "usr/bin/redis-server",
        )
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise HarnessError(f"black-box runtime is not provisioned; missing: {missing}")

    def _verify_inputs(self) -> None:
        self._verify_backend_inputs()
        required = (
            self.paths.runtime / "jdk22" / "bin" / "java",
            self.paths.oracle_jar,
            self.paths.java_manifest,
        )
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise HarnessError(f"black-box runtime is not provisioned; missing: {missing}")

        manifest = json.loads(self.paths.java_manifest.read_text(encoding="utf-8"))
        oracle = manifest["oracle_jar"]
        expected = str(oracle["selected_sha256"]).lower()
        with self.paths.oracle_jar.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != expected:
            raise HarnessError(f"Java oracle SHA-256 is not frozen: {digest}; expected {expected}")

    @staticmethod
    def _run_checked(
        argv: list[str],
        *,
        env: dict[str, str],
        log_path: Path,
        timeout: float = 30.0,
    ) -> None:
        with log_path.open("ab") as log:
            # All argv values come from the pinned local runtime and generated temp paths.
            completed = subprocess.run(  # noqa: S603
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        if completed.returncode != 0:
            tail = log_path.read_bytes()[-16_384:].decode("utf-8", errors="replace")
            raise ProcessStartError(
                f"command exited with {completed.returncode}: {argv[0]}; tail:\n{tail}"
            )

    def _base_environment(self) -> dict[str, str]:
        workspace, _ = self._require_state()
        return {
            "HOME": str(workspace / "home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(workspace / "tmp"),
            "TZ": "UTC",
        }

    def _postgres_env(self) -> dict[str, str]:
        root = self.paths.runtime / "postgres-root"
        env = self._base_environment()
        env["LD_LIBRARY_PATH"] = str(root / "usr/lib/x86_64-linux-gnu")
        env["PATH"] = f"{root / 'usr/lib/postgresql/16/bin'}:/usr/bin:/bin"
        return env

    def _wait_for_postgres_ready(
        self,
        bin_dir: Path,
        port: int,
        *,
        env: dict[str, str],
        log_path: Path,
        timeout: float = 20.0,
    ) -> None:
        deadline = time.monotonic() + timeout
        last_error: ProcessStartError | None = None
        while time.monotonic() < deadline:
            try:
                self._run_checked(
                    [
                        str(bin_dir / "pg_isready"),
                        "--host=127.0.0.1",
                        f"--port={port}",
                        "--username=lmyzmail_test",
                        "--dbname=postgres",
                        "--timeout=1",
                    ],
                    env=env,
                    log_path=log_path,
                    timeout=2.0,
                )
                return
            except ProcessStartError as error:
                last_error = error
                time.sleep(0.05)
        raise ProcessStartError(
            f"PostgreSQL did not become ready within {timeout}s: {last_error}; "
            f"tail:\n{self._postgres.log_tail() if self._postgres else '<no process>'}"
        )

    def _redis_env(self) -> dict[str, str]:
        root = self.paths.runtime / "redis-root"
        env = self._base_environment()
        env["LD_LIBRARY_PATH"] = str(root / "usr/lib/x86_64-linux-gnu")
        return env

    def _require_state(self) -> tuple[Path, PortSet]:
        if self.workspace is None or self.ports is None:
            raise RuntimeError("JavaOracleRuntime is not in a started state")
        return self.workspace, self.ports

    def _start_postgres(self) -> None:
        workspace, ports = self._require_state()
        if self._port_allocator is None:
            raise RuntimeError("port allocator is not available")
        root = self.paths.runtime / "postgres-root"
        bin_dir = root / "usr/lib/postgresql/16/bin"
        data = workspace / "postgres-data"
        socket_dir = workspace / "postgres-socket"
        socket_dir.mkdir()
        log = workspace / "postgres.log"
        env = self._postgres_env()
        self._run_checked(
            [
                str(bin_dir / "initdb"),
                "--pgdata",
                str(data),
                "--username=lmyzmail_test",
                "--auth=trust",
                "--encoding=UTF8",
                "--no-locale",
            ],
            env=env,
            log_path=log,
        )
        self._port_allocator.release_port(ports.postgres)
        self._postgres = ManagedProcess(
            "postgres",
            [
                str(bin_dir / "postgres"),
                "-D",
                str(data),
                "-h",
                "127.0.0.1",
                "-p",
                str(ports.postgres),
                "-k",
                str(socket_dir),
                "-c",
                "fsync=off",
                "-c",
                "synchronous_commit=off",
                "-c",
                "full_page_writes=off",
                "-c",
                "max_connections=128",
            ],
            log,
            env=env,
            inherit_env=False,
        )
        self._postgres.start()
        self._postgres.wait_for_tcp("127.0.0.1", ports.postgres, timeout=20.0)
        self._wait_for_postgres_ready(
            bin_dir,
            ports.postgres,
            env=env,
            log_path=log,
        )
        self._run_checked(
            [
                str(bin_dir / "createdb"),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "lmyzmail",
            ],
            env=env,
            log_path=log,
        )

    def _start_redis(self) -> None:
        workspace, ports = self._require_state()
        if self._port_allocator is None:
            raise RuntimeError("port allocator is not available")
        self._port_allocator.release_port(ports.redis)
        data = workspace / "redis-data"
        data.mkdir()
        root = self.paths.runtime / "redis-root"
        self._redis = ManagedProcess(
            "redis",
            [
                str(root / "usr/bin/redis-server"),
                "--bind",
                "127.0.0.1",
                "--port",
                str(ports.redis),
                "--protected-mode",
                "yes",
                "--daemonize",
                "no",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                str(data),
            ],
            workspace / "redis.log",
            env=self._redis_env(),
            inherit_env=False,
        )
        self._redis.start()
        self._redis.wait_for_tcp("127.0.0.1", ports.redis, timeout=10.0)
        redis_stream = connect_bounded("127.0.0.1", ports.redis, timeout=2.0)
        try:
            redis_stream.sendall(b"*1\r\n$4\r\nPING\r\n")
            if redis_stream.read_line() != b"+PONG\r\n":
                raise ProcessStartError("Redis readiness probe did not return PONG")
        finally:
            redis_stream.sock.close()

    def _application_arguments(self) -> list[str]:
        workspace, ports = self._require_state()
        arguments = [
            str(self.paths.runtime / "jdk22/bin/java"),
            "--enable-preview",
            "--enable-native-access=ALL-UNNAMED",
            f"-Djava.io.tmpdir={workspace / 'java-tmp'}",
            f"-Duser.home={workspace / 'home'}",
            "-Duser.timezone=UTC",
            "-jar",
            str(self.paths.oracle_jar),
            "--spring.config.location=optional:classpath:/application.properties",
            (f"--spring.datasource.url=jdbc:postgresql://127.0.0.1:{ports.postgres}/lmyzmail"),
            "--spring.datasource.driver-class-name=org.postgresql.Driver",
            "--spring.datasource.username=lmyzmail_test",
            "--spring.datasource.password=",
            "--spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect",
            "--spring.jpa.hibernate.ddl-auto=create-drop",
            "--spring.data.redis.host=127.0.0.1",
            f"--spring.data.redis.port={ports.redis}",
            "--spring.data.redis.database=0",
            "--spring.data.redis.lettuce.pool.max-active=16",
            "--spring.data.redis.lettuce.pool.max-idle=8",
            "--spring.data.redis.lettuce.pool.min-idle=1",
            "--botmail.netty.http.enabled=true",
            f"--botmail.netty.http.port={ports.http}",
            "--botmail.netty.http.trusted-proxies=127.0.0.1,::1",
            "--botmail.smtp.bind-address=127.0.0.1",
            f"--botmail.smtp.port={ports.smtp}",
            "--botmail.smtp.skibidi-generator-mode=JAVA",
            "--botmail.smtp-security.spamhaus-enabled=false",
            "--botmail.smtp-security.spamhaus-dbl-enabled=false",
            "--botmail.smtp-security.tarpit-enabled=false",
            "--botmail.smtp.mta-sts-enabled=false",
            "--botmail.ssl.use-custom-certificate=false",
            "--botmail.htcpcp.enabled=true",
            f"--botmail.htcpcp.port={ports.htcpcp}",
            "--botmail.minecraft.enabled=true",
            f"--botmail.minecraft.port={ports.minecraft}",
            "--botmail.minecraft.online-mode=false",
            "--botmail.honeypot.enabled=true",
            "--botmail.honeypot.initial-delay-ms=25",
            "--botmail.honeypot.post-banner-timeout-ms=500",
            "--botmail.xdp.enabled=false",
            "--botmail.xdp.pps-monitor.enabled=false",
            "--botmail.fail2ban.enabled=false",
            f"--botmail.maildir.base={workspace / 'maildir'}",
            "--botmail.domains.main.domain=example.test",
            "--botmail.domains.main.receiveEnabled=true",
            "--botmail.domains.main.sendEnabled=true",
            "--botmail.domains.main.requireExistingMailbox=true",
            f"--botmail.api-keys[0].key={API_KEY}",
            "--botmail.api-keys[0].label=blackbox-admin",
            "--botmail.api-keys[0].readEnabled=true",
            "--botmail.api-keys[0].writeEnabled=true",
            f"--botmail.api-keys[1].key={READ_ONLY_API_KEY}",
            "--botmail.api-keys[1].label=blackbox-read",
            "--botmail.api-keys[1].readEnabled=true",
            "--botmail.api-keys[1].writeEnabled=false",
            f"--botmail.api-keys[2].key={WRITE_ONLY_API_KEY}",
            "--botmail.api-keys[2].label=blackbox-write",
            "--botmail.api-keys[2].readEnabled=false",
            "--botmail.api-keys[2].writeEnabled=true",
            f"--botmail.allowed-origins[0]=http://127.0.0.1:{ports.http}",
            "--botmail.public-registration-enabled=true",
            "--botmail.index.migration-enabled=false",
            "--botmail.reporting.enabled=true",
            "--botmail.reporting.auto-send-enabled=false",
            "--botmail.reporting.http-delivery-enabled=false",
            "--spring.datasource.hikari.minimum-idle=2",
            "--spring.datasource.hikari.maximum-pool-size=16",
            f"--logging.file.name={workspace / 'java-application.log'}",
        ]
        protocols = ("MYSQL", "SSH", "VNC", "NONE", "NONE", "NONE", "FTP", "VNC")
        for index, (port, protocol) in enumerate(zip(ports.honeypots, protocols, strict=True)):
            arguments.extend(
                (
                    f"--botmail.honeypot.traps[{index}].port={port}",
                    f"--botmail.honeypot.traps[{index}].label=trap-{index}",
                    f"--botmail.honeypot.traps[{index}].server-protocol={protocol}",
                    f"--botmail.honeypot.traps[{index}].bind-address=127.0.0.1",
                )
            )
        return arguments

    def _application_environment(self) -> dict[str, str]:
        workspace, _ = self._require_state()
        return {
            **self._base_environment(),
            "XDG_CACHE_HOME": str(workspace / "xdg-cache"),
            "XDG_CONFIG_HOME": str(workspace / "xdg-config"),
            "XDG_DATA_HOME": str(workspace / "xdg-data"),
        }

    def _application_service_ports(self) -> tuple[int, ...]:
        _, ports = self._require_state()
        return (
            ports.http,
            ports.smtp,
            ports.htcpcp,
            ports.minecraft,
            *ports.honeypots,
        )

    @staticmethod
    def _probe_smtp_readiness(host: str, port: int, *, timeout: float) -> None:
        stream = connect_bounded(host, port, timeout=timeout, max_received=64 * 1024)
        try:
            greeting = read_smtp_reply(stream)
            if not greeting or greeting[0][:3] != b"220":
                raise ProtocolError(f"SMTP server did not greet with 220: {greeting!r}")
        finally:
            stream.sock.close()

    def _start_application(self) -> None:
        workspace, ports = self._require_state()
        if self._port_allocator is None:
            raise RuntimeError("port allocator is not available")
        if not self._application_ports_released:
            for port in self._application_service_ports():
                self._port_allocator.release_port(port)
            self._application_ports_released = True
        for directory in (
            "home",
            "java-tmp",
            "tmp",
            "xdg-cache",
            "xdg-config",
            "xdg-data",
        ):
            (workspace / directory).mkdir(exist_ok=True)
        self._application = ManagedProcess(
            self.target_kind,
            self._application_arguments(),
            workspace / f"{self.target_kind}.log",
            cwd=workspace,
            env=self._application_environment(),
            inherit_env=False,
        )
        self._application.start()
        deadline = time.monotonic() + self.startup_timeout

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProcessStartError(
                f"{self.target_kind} startup deadline expired before HTTP listen"
            )
        self._application.wait_for_tcp("127.0.0.1", ports.http, timeout=remaining)

        health_url = f"http://127.0.0.1:{ports.http}/api/health"
        last_error: Exception | None = None
        with httpx.Client(trust_env=False, timeout=1.0) as client:
            health_ready = False
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    response = client.get(health_url, timeout=min(1.0, remaining))
                    if response.status_code == 200:
                        health_ready = True
                        break
                    last_error = RuntimeError(f"health returned {response.status_code}")
                except httpx.HTTPError as error:
                    last_error = error
                sleep_for = min(0.1, deadline - time.monotonic())
                if sleep_for > 0:
                    time.sleep(sleep_for)

        if not health_ready:
            raise ProcessStartError(
                f"{self.target_kind} HTTP health did not become ready: {last_error}; "
                f"tail:\n{self._application.log_tail()}"
            )

        last_error = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self._probe_smtp_readiness(
                    "127.0.0.1",
                    ports.smtp,
                    timeout=min(1.0, remaining),
                )
                return
            except (OSError, ProtocolError) as error:
                last_error = error
            sleep_for = min(0.1, deadline - time.monotonic())
            if sleep_for > 0:
                time.sleep(sleep_for)

        raise ProcessStartError(
            f"{self.target_kind} SMTP readiness did not become ready: {last_error}; "
            f"tail:\n{self._application.log_tail()}"
        )

    def _create_qa_account(self) -> None:
        _, ports = self._require_state()
        with httpx.Client(trust_env=False, timeout=10.0) as client:
            response = client.post(
                f"http://127.0.0.1:{ports.http}/web/register",
                json={"address": QA_ADDRESS, "password": QA_PASSWORD},
            )
        if response.status_code != 201:
            raise ProcessStartError(
                f"QA registration failed with {response.status_code}: {response.text[:1000]}"
            )

    def start(self) -> Self:
        if self.workspace is not None:
            raise RuntimeError("JavaOracleRuntime may only start once")
        self._verify_inputs()
        self._temporary = tempfile.TemporaryDirectory(prefix="lmyzmail-blackbox-")
        self.workspace = Path(self._temporary.name)
        for directory in (
            "home",
            "java-tmp",
            "tmp",
            "xdg-cache",
            "xdg-config",
            "xdg-data",
        ):
            (self.workspace / directory).mkdir()
        self._port_allocator = PortAllocator()
        self.ports = self._port_allocator.reserve_all(honeypot_count=8)
        self._application_ports_released = False
        try:
            self._start_postgres()
            self._start_redis()
            self._start_application()
            self._create_qa_account()
        except BaseException:
            self.stop()
            raise
        return self

    def stop(self) -> None:
        first_error: BaseException | None = None
        processes = tuple(
            process
            for process in (self._application, self._redis, self._postgres)
            if process is not None
        )
        try:
            stop_managed_processes(
                processes,
                grace_timeout=self.shutdown_timeout,
                kill_timeout=self.shutdown_kill_timeout,
            )
        except BaseException as error:
            first_error = error
        self._application = None
        self._redis = None
        self._postgres = None
        if self._port_allocator is not None:
            self._port_allocator.release()
        self._port_allocator = None
        if self._temporary is not None:
            self._temporary.cleanup()
        self._temporary = None
        self.workspace = None
        self.ports = None
        if first_error is not None:
            raise first_error

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()


@dataclass(slots=True)
class JavaOracleTlsRuntime(JavaOracleRuntime):
    _tls_material: EphemeralTlsMaterial | None = field(default=None, init=False, repr=False)

    @property
    def tls_certificate_pem(self) -> bytes:
        if self._tls_material is None:
            raise HarnessError("managed Java STARTTLS runtime is not started")
        return self._tls_material.certificate_pem

    @property
    def tls_keystore_path(self) -> Path:
        if self._tls_material is None:
            raise HarnessError("managed Java STARTTLS runtime is not started")
        return self._tls_material.keystore_path

    def _application_arguments(self) -> list[str]:
        workspace, _ = self._require_state()
        if self._tls_material is None:
            self._tls_material = provision_ephemeral_tls_material(workspace)

        arguments = JavaOracleRuntime._application_arguments(self)
        disabled = "--botmail.ssl.use-custom-certificate=false"
        try:
            index = arguments.index(disabled)
        except ValueError as error:
            raise HarnessError("managed Java arguments lost the explicit TLS default") from error
        arguments[index] = "--botmail.ssl.use-custom-certificate=true"
        arguments.append(f"--botmail.ssl.keystore-path={self._tls_material.keystore_path}")
        return arguments

    def _application_environment(self) -> dict[str, str]:
        environment = JavaOracleRuntime._application_environment(self)
        if self._tls_material is None:
            raise HarnessError("managed Java STARTTLS material is not provisioned")
        environment["BOTMAIL_SSL_KEYSTORE_PASSWORD"] = self._tls_material.keystore_password
        return environment

    def stop(self) -> None:
        try:
            JavaOracleRuntime.stop(self)
        finally:
            self._tls_material = None


@dataclass(slots=True)
class CandidateRuntime(JavaOracleRuntime):
    """Launch an external candidate through a shell-free command template.

    Template fields expose only isolated runtime paths and ports. The candidate or a
    separately tested launch adapter consumes the generated semantic configuration.
    """

    command_template: tuple[str, ...] = ()

    @property
    def target_kind(self) -> str:
        return "rust-candidate"

    @classmethod
    def from_environment(cls) -> CandidateRuntime:
        raw = os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON")
        if raw is None:
            raise HarnessError("LMYZMAIL_CANDIDATE_COMMAND_JSON is not set")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise HarnessError("candidate command is not valid JSON") from error
        if (
            not isinstance(parsed, list)
            or not parsed
            or not all(isinstance(value, str) and value for value in parsed)
        ):
            raise HarnessError("candidate command must be a non-empty JSON string array")
        return cls(command_template=tuple(parsed))

    def _verify_inputs(self) -> None:
        self._verify_backend_inputs()
        if not self.command_template:
            raise HarnessError("candidate command template is empty")
        executable = Path(self.command_template[0])
        if not executable.is_absolute():
            executable = self.paths.repository / executable
        executable = executable.resolve()
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise HarnessError(f"candidate executable is missing or not executable: {executable}")
        self.command_template = (str(executable), *self.command_template[1:])

    def _candidate_configuration(self) -> Path:
        workspace, ports = self._require_state()
        protocols = ("MYSQL", "SSH", "VNC", "NONE", "NONE", "NONE", "FTP", "VNC")
        value = {
            "schema_version": 1,
            "profile": "managed-basic",
            "listen": {
                "host": "127.0.0.1",
                "http": ports.http,
                "smtp": ports.smtp,
                "htcpcp": ports.htcpcp,
                "minecraft": ports.minecraft,
                "honeypots": [
                    {"port": port, "protocol": protocol, "label": f"trap-{index}"}
                    for index, (port, protocol) in enumerate(
                        zip(ports.honeypots, protocols, strict=True)
                    )
                ],
            },
            "postgres": {
                "host": "127.0.0.1",
                "port": ports.postgres,
                "database": "lmyzmail",
                "username": "lmyzmail_test",
                "password": "",
            },
            "redis": {"host": "127.0.0.1", "port": ports.redis, "database": 0},
            "maildir": str(workspace / "maildir"),
            "domain": "example.test",
            "api_keys": [
                {
                    "key": API_KEY,
                    "label": "blackbox-admin",
                    "read": True,
                    "write": True,
                },
                {
                    "key": READ_ONLY_API_KEY,
                    "label": "blackbox-read",
                    "read": True,
                    "write": False,
                },
                {
                    "key": WRITE_ONLY_API_KEY,
                    "label": "blackbox-write",
                    "read": False,
                    "write": True,
                },
            ],
            "features": {
                "public_registration": True,
                "smtp_skibidi_mode": "AUTO_SAFE",
                "spamhaus": False,
                "tarpit": False,
                "mta_sts": False,
                "xdp": False,
                "fail2ban": False,
                "report_delivery": False,
            },
            "limits": {
                "redis_pool": 16,
                "postgres_pool": 16,
                "honeypot_initial_delay_ms": 25,
                "honeypot_post_banner_timeout_ms": 500,
            },
        }
        path = workspace / "candidate-runtime.json"
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def _application_arguments(self) -> list[str]:
        workspace, ports = self._require_state()
        config = self._candidate_configuration()
        fields = {
            "config": str(config),
            "workspace": str(workspace),
            "http_port": str(ports.http),
            "smtp_port": str(ports.smtp),
            "htcpcp_port": str(ports.htcpcp),
            "minecraft_port": str(ports.minecraft),
            "postgres_port": str(ports.postgres),
            "redis_port": str(ports.redis),
            **{f"honeypot_{index}_port": str(port) for index, port in enumerate(ports.honeypots)},
        }
        try:
            return [value.format_map(fields) for value in self.command_template]
        except KeyError as error:
            raise HarnessError(f"unknown candidate command template field: {error}") from error
