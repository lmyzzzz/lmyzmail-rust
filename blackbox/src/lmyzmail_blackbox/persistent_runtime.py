from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from enum import Enum
from pathlib import Path
from typing import Literal, Self, cast

import httpx
import redis

from .errors import HarnessError, ProcessStartError
from .golden import canonical_json
from .legacy_storage import (
    apply_redis_seed,
    install_maildir_fixture,
    load_redis_seed,
    snapshot_redis_seed,
)
from .ports import PortAllocator
from .processes import ManagedProcess, kill_managed_processes
from .protocols import connect_bounded
from .runtime import HarnessPaths, JavaOracleRuntime
from .sql_fixture import normalize_postgres_schema_dump

LEGACY_SESSION_TOKEN = "legacy-session-token"  # noqa: S105
_REDIS_SENTINEL_KEY = "lmyzmail:blackbox:persistent-runtime:v1"
_GENERATION_LOG = re.compile(
    r"^(?:java-oracle-persistent|java-application|postgres|redis)-(\d+)\.log$"
)


class PersistentRuntimeState(Enum):
    NEW = "new"
    RUNNING = "running"
    STOPPED = "stopped"
    CRASHED = "crashed"
    CLEANUP_FAILED = "cleanup_failed"
    CLOSED = "closed"


class PersistentJavaOracleRuntime(JavaOracleRuntime):
    """Production-like durable oracle runtime over a caller-owned workspace."""

    def __init__(
        self,
        workspace_path: Path,
        *,
        paths: HarnessPaths | None = None,
        startup_timeout: float = 90.0,
        shutdown_timeout: float = 5.0,
        shutdown_kill_timeout: float = 2.0,
        index_migration_enabled: bool = False,
        redis_mode: Literal["both", "rdb-only"] = "both",
    ) -> None:
        super().__init__(
            paths=paths or HarnessPaths.discover(),
            startup_timeout=startup_timeout,
            shutdown_timeout=shutdown_timeout,
            shutdown_kill_timeout=shutdown_kill_timeout,
        )
        if os.name != "posix":
            raise HarnessError("persistent runtime is supported only on Linux")
        workspace = workspace_path.absolute()
        current = workspace
        while not current.exists() and current != current.parent:
            current = current.parent
        while current != current.parent:
            if current.is_symlink():
                raise HarnessError(f"persistent workspace parent is symlinked: {current}")
            current = current.parent
        if workspace.exists() and (workspace.is_symlink() or not workspace.is_dir()):
            raise HarnessError(f"persistent workspace is not a real directory: {workspace}")
        self.persistent_workspace = workspace
        self.workspace = workspace
        self.generation = self._discover_generation()
        self.index_migration_enabled = index_migration_enabled
        if redis_mode not in {"both", "rdb-only"}:
            raise ValueError(f"unsupported persistent Redis mode: {redis_mode}")
        self.redis_mode = redis_mode
        marker = self._marker_path()
        if marker.exists() or marker.is_symlink():
            if marker.is_symlink() or not marker.is_file():
                raise HarnessError(f"persistent runtime attestation is not a real file: {marker}")
            self.state = PersistentRuntimeState.STOPPED
        else:
            self.state = PersistentRuntimeState.NEW

    @property
    def target_kind(self) -> str:
        return f"java-oracle-persistent-{self.generation:04d}"

    def _marker_path(self) -> Path:
        return self.persistent_workspace / "lmyzmail-runtime-attestation.json"

    def _discover_generation(self) -> int:
        if not self.persistent_workspace.is_dir():
            return 0
        generations = [
            int(match.group(1))
            for path in self.persistent_workspace.iterdir()
            if (match := _GENERATION_LOG.fullmatch(path.name)) is not None
        ]
        return max(generations, default=0)

    @staticmethod
    def _sha256(path: Path) -> str:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def _schema_metadata(self) -> dict[str, object]:
        path = self.paths.repository / "blackbox/fixtures/legacy/postgres-schema.json"
        try:
            value: object = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise HarnessError(f"invalid PostgreSQL schema metadata: {path}") from error
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise HarnessError(f"unsupported PostgreSQL schema metadata: {path}")
        metadata = cast(dict[str, object], value)
        for key in ("schema_sha256", "roundtrip_schema_sha256"):
            digest = metadata.get(key)
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise HarnessError(f"invalid {key} in PostgreSQL schema metadata")
        return metadata

    def _expected_attestation(self) -> dict[str, object]:
        fixture_root = self.paths.repository / "blackbox/fixtures/legacy"
        oracle_manifest = json.loads(self.paths.java_manifest.read_text(encoding="utf-8"))
        return {
            "schema_version": 1,
            "oracle": {
                "commit": str(oracle_manifest["commit"]),
                "jar_sha256": str(oracle_manifest["oracle_jar"]["selected_sha256"]),
            },
            "runtime": {
                "index_migration_enabled": self.index_migration_enabled,
                "redis_mode": self.redis_mode,
            },
            "fixtures": {
                "postgres_schema_sha256": self._sha256(fixture_root / "postgres-schema.sql"),
                "postgres_schema_metadata_sha256": self._sha256(
                    fixture_root / "postgres-schema.json"
                ),
                "postgres_seed_sha256": self._sha256(fixture_root / "postgres-seed.sql"),
                "redis_seed_sha256": self._sha256(fixture_root / "redis-seed.json"),
                "maildir_manifest_sha256": self._sha256(fixture_root / "maildir.json"),
            },
        }

    def _redis_sentinel(self) -> bytes:
        return hashlib.sha256(canonical_json(self._expected_attestation())).hexdigest().encode()

    def _write_attestation(self) -> None:
        path = self._marker_path()
        value = canonical_json(self._expected_attestation())
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError as error:
                raise HarnessError(f"runtime attestation already exists: {path}") from error
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def _verify_attestation(self) -> None:
        path = self._marker_path()
        if path.is_symlink() or not path.is_file():
            raise HarnessError(f"invalid persistent runtime attestation path: {path}")
        try:
            actual = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise HarnessError(f"invalid persistent runtime attestation: {path}") from error
        expected = self._expected_attestation()
        if actual != expected:
            raise HarnessError(
                f"persistent runtime attestation mismatch: actual={actual!r}, expected={expected!r}"
            )

    def _prepare_workspace(self, *, new_workspace: bool) -> None:
        if self.persistent_workspace.is_symlink() or (
            self.persistent_workspace.exists() and not self.persistent_workspace.is_dir()
        ):
            raise HarnessError(
                f"persistent workspace is not a real directory: {self.persistent_workspace}"
            )
        if (
            new_workspace
            and self.persistent_workspace.exists()
            and any(self.persistent_workspace.iterdir())
        ):
            raise HarnessError(
                f"refusing to initialize non-empty persistent workspace: "
                f"{self.persistent_workspace}"
            )
        self.persistent_workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.persistent_workspace, 0o700)
        for directory in (
            "home",
            "java-tmp",
            "tmp",
            "xdg-cache",
            "xdg-config",
            "xdg-data",
        ):
            path = self.persistent_workspace / directory
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                raise HarnessError(f"persistent workspace subdirectory is invalid: {path}")
            path.mkdir(exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)

    def _allocate_ports(self) -> None:
        if self._port_allocator is not None:
            raise RuntimeError("persistent runtime already owns a port allocator")
        self._port_allocator = PortAllocator()
        self.ports = self._port_allocator.reserve_all(honeypot_count=8)
        self._application_ports_released = False

    def _release_ports(self) -> None:
        if self._port_allocator is not None:
            self._port_allocator.release()
        self._port_allocator = None

    def _initialize_postgres(self, bin_dir: Path, log: Path, env: dict[str, str]) -> None:
        data = self.persistent_workspace / "postgres-data"
        if data.exists() or data.is_symlink():
            raise HarnessError(f"refusing to initialize existing PostgreSQL data path: {data}")
        self._run_checked(
            [
                str(bin_dir / "initdb"),
                "--pgdata",
                str(data),
                "--username=lmyzmail_test",
                "--auth=trust",
                "--encoding=UTF8",
                "--no-locale",
                "--data-checksums",
            ],
            env=env,
            log_path=log,
        )

    def _apply_postgres_fixtures(self, bin_dir: Path, log: Path, env: dict[str, str]) -> None:
        _, ports = self._require_state()
        fixture_root = self.paths.repository / "blackbox/fixtures/legacy"
        schema = fixture_root / "postgres-schema.sql"
        seed = fixture_root / "postgres-seed.sql"
        schema_metadata = self._schema_metadata()
        if self._sha256(schema) != str(schema_metadata["schema_sha256"]):
            raise HarnessError("PostgreSQL schema fixture does not match its metadata")
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
        self._run_checked(
            [
                str(bin_dir / "psql"),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--single-transaction",
                "--set=ON_ERROR_STOP=1",
                '--command=DROP SCHEMA "public";',
                f"--file={schema}",
                f"--file={seed}",
            ],
            env=env,
            log_path=log,
        )

    def _verify_postgres_schema(self, bin_dir: Path, log: Path, env: dict[str, str]) -> None:
        _, ports = self._require_state()
        descriptor, dump_name = tempfile.mkstemp(
            prefix=".postgres-schema-", suffix=".sql", dir=self.persistent_workspace
        )
        os.close(descriptor)
        dump = Path(dump_name)
        try:
            self._run_checked(
                [
                    str(bin_dir / "pg_dump"),
                    "--host=127.0.0.1",
                    f"--port={ports.postgres}",
                    "--username=lmyzmail_test",
                    "--dbname=lmyzmail",
                    "--schema=public",
                    "--schema-only",
                    "--no-owner",
                    "--no-privileges",
                    "--no-comments",
                    "--quote-all-identifiers",
                    f"--file={dump}",
                ],
                env=env,
                log_path=log,
            )
            actual = normalize_postgres_schema_dump(dump.read_bytes())
        finally:
            dump.unlink(missing_ok=True)
        metadata = self._schema_metadata()
        expected_digest = str(metadata["roundtrip_schema_sha256"])
        actual_digest = hashlib.sha256(actual).hexdigest()
        if actual_digest != expected_digest:
            raise HarnessError(
                "persistent PostgreSQL schema drifted from the attested fixture: "
                f"actual={actual_digest}, expected={expected_digest}"
            )

    def _start_persistent_postgres(self, *, initialize: bool) -> None:
        _, ports = self._require_state()
        if self._port_allocator is None:
            raise RuntimeError("port allocator is not available")
        root = self.paths.runtime / "postgres-root"
        bin_dir = root / "usr/lib/postgresql/16/bin"
        log = self.persistent_workspace / f"postgres-{self.generation:04d}.log"
        env = self._postgres_env()
        data = self.persistent_workspace / "postgres-data"
        if initialize:
            self._initialize_postgres(bin_dir, log, env)
        else:
            version = data / "PG_VERSION"
            if (
                data.is_symlink()
                or not data.is_dir()
                or version.is_symlink()
                or not version.is_file()
            ):
                raise HarnessError("persistent PostgreSQL cluster is missing or symlinked")
        self._port_allocator.release_port(ports.postgres)
        self._postgres = ManagedProcess(
            f"postgres-persistent-{self.generation:04d}",
            [
                str(bin_dir / "postgres"),
                "-D",
                str(data),
                "-h",
                "127.0.0.1",
                "-p",
                str(ports.postgres),
                "-c",
                "fsync=on",
                "-c",
                "synchronous_commit=on",
                "-c",
                "full_page_writes=on",
                "-c",
                "max_connections=128",
                "-c",
                "unix_socket_directories=",
            ],
            log,
            env=env,
            inherit_env=False,
        )
        self._postgres.start()
        self._postgres.wait_for_tcp("127.0.0.1", ports.postgres, timeout=20.0)
        self._wait_for_postgres_ready(bin_dir, ports.postgres, env=env, log_path=log, timeout=20.0)
        if initialize:
            self._apply_postgres_fixtures(bin_dir, log, env)
        self._verify_postgres_schema(bin_dir, log, env)

    def _wait_for_redis_ready(self, port: int, *, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        last_error: BaseException | None = None
        while time.monotonic() < deadline:
            try:
                stream = connect_bounded("127.0.0.1", port, timeout=1.0)
                try:
                    stream.sendall(b"*1\r\n$4\r\nPING\r\n")
                    if stream.read_line() == b"+PONG\r\n":
                        return
                finally:
                    stream.sock.close()
            except (OSError, HarnessError) as error:
                last_error = error
            time.sleep(0.05)
        raise ProcessStartError(f"persistent Redis did not become ready: {last_error}")

    def _start_persistent_redis(self, *, initialize: bool) -> None:
        _, ports = self._require_state()
        if self._port_allocator is None:
            raise RuntimeError("port allocator is not available")
        data = self.persistent_workspace / "redis-data"
        if data.is_symlink() or (data.exists() and not data.is_dir()):
            raise HarnessError(f"persistent Redis data path is invalid: {data}")
        data.mkdir(exist_ok=True, mode=0o700)
        os.chmod(data, 0o700)
        dump = data / "dump.rdb"
        append_directory = data / "appendonlydir"
        append_manifest = append_directory / "appendonly.aof.manifest"
        for path in (dump, append_directory, append_manifest):
            if path.is_symlink():
                raise HarnessError(f"persistent Redis path is symlinked: {path}")
        if not initialize:
            if self.redis_mode == "both" and (
                not dump.is_file() or not append_directory.is_dir() or not append_manifest.is_file()
            ):
                raise HarnessError("persistent Redis AOF or RDB persistence is missing")
            if self.redis_mode == "rdb-only" and not dump.is_file():
                raise HarnessError("persistent Redis RDB snapshot is missing")
        root = self.paths.runtime / "redis-root"
        self._port_allocator.release_port(ports.redis)
        persistence_arguments = (
            [
                "--appendonly",
                "yes",
                "--appendfsync",
                "always",
                "--no-appendfsync-on-rewrite",
                "no",
                "--auto-aof-rewrite-percentage",
                "0",
                "--aof-use-rdb-preamble",
                "yes",
                "--appenddirname",
                "appendonlydir",
            ]
            if self.redis_mode == "both"
            else ["--appendonly", "no"]
        )
        self._redis = ManagedProcess(
            f"redis-persistent-{self.generation:04d}",
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
                "--dir",
                str(data),
                *persistence_arguments,
                "--dbfilename",
                "dump.rdb",
                "--save",
                "60 1",
            ],
            self.persistent_workspace / f"redis-{self.generation:04d}.log",
            env=self._redis_env(),
            inherit_env=False,
        )
        self._redis.start()
        self._redis.wait_for_tcp("127.0.0.1", ports.redis, timeout=10.0)
        self._wait_for_redis_ready(ports.redis)
        if initialize:
            fixture = load_redis_seed(self.paths.repository)
            client = redis.Redis(
                host="127.0.0.1",
                port=ports.redis,
                db=fixture.database,
                socket_connect_timeout=5.0,
                socket_timeout=5.0,
            )
            try:
                if cast(int, client.dbsize()) != 0:
                    raise HarnessError("persistent Redis was not empty before fixture load")
                apply_redis_seed(client, fixture)
                if not cast(bool, client.set(_REDIS_SENTINEL_KEY, self._redis_sentinel(), nx=True)):
                    raise HarnessError("persistent Redis sentinel already existed")
                snapshot_redis_seed(client, fixture)
                if not cast(bool, client.save()):
                    raise HarnessError("Redis SAVE did not report success")
            finally:
                client.close()
        else:
            client = redis.Redis(
                host="127.0.0.1",
                port=ports.redis,
                socket_connect_timeout=5.0,
                socket_timeout=5.0,
            )
            try:
                if client.get(_REDIS_SENTINEL_KEY) != self._redis_sentinel():
                    raise HarnessError("persistent Redis sentinel is missing or invalid")
            finally:
                client.close()

    def _application_arguments(self) -> list[str]:
        arguments = super()._application_arguments()
        replaced_prefixes = (
            "--spring.jpa.hibernate.ddl-auto=",
            "--botmail.index.migration-enabled=",
            "--botmail.maildir.max-files-per-directory=",
            "--logging.file.name=",
        )
        arguments = [
            argument for argument in arguments if not argument.startswith(replaced_prefixes)
        ]
        arguments.extend(
            (
                "--spring.jpa.hibernate.ddl-auto=validate",
                ("--botmail.index.migration-enabled=" + str(self.index_migration_enabled).lower()),
                "--botmail.maildir.max-files-per-directory=1",
                (
                    "--logging.file.name="
                    f"{self.persistent_workspace / f'java-application-{self.generation:04d}.log'}"
                ),
            )
        )
        for prefix in replaced_prefixes:
            if sum(argument.startswith(prefix) for argument in arguments) != 1:
                raise AssertionError(f"persistent application property is not unique: {prefix}")
        return arguments

    def _start_application(self) -> None:
        super()._start_application()
        if self._application is None:
            raise RuntimeError("persistent application process is not available")
        _, ports = self._require_state()
        deadline = time.monotonic() + self.startup_timeout
        markers = (
            "Started 2 outbound persist worker threads",
            "Redis connection is healthy",
        )
        last_error: BaseException | None = None
        url = f"http://127.0.0.1:{ports.http}/web/mail/list/inbox?page=0&size=1"
        with httpx.Client(trust_env=False, timeout=1.0) as client:
            while time.monotonic() < deadline:
                log_tail = self._application.log_tail(max_bytes=256 * 1024)
                if all(marker in log_tail for marker in markers):
                    try:
                        response = client.get(
                            url,
                            headers={"X-Session-Token": LEGACY_SESSION_TOKEN},
                        )
                        if response.status_code == 200:
                            return
                        last_error = RuntimeError(
                            f"persistent readiness returned {response.status_code}"
                        )
                    except httpx.HTTPError as error:
                        last_error = error
                time.sleep(0.05)
        raise ProcessStartError(
            f"persistent application did not finish ApplicationReady: {last_error}; "
            f"tail:\n{self._application.log_tail()}"
        )

    def _force_cleanup_after_start_failure(self) -> None:
        processes = tuple(
            process
            for process in (self._application, self._redis, self._postgres)
            if process is not None
        )
        kill_managed_processes(processes, kill_timeout=self.shutdown_kill_timeout)
        self._application = None
        self._redis = None
        self._postgres = None
        self._release_ports()

    def _record_start_failure(self, error: BaseException) -> None:
        try:
            self._force_cleanup_after_start_failure()
        except BaseException as cleanup_error:
            self.state = PersistentRuntimeState.CLEANUP_FAILED
            error.add_note(f"persistent runtime cleanup also failed: {cleanup_error}")
            raise error from cleanup_error
        self.state = PersistentRuntimeState.CRASHED

    def start(self) -> Self:
        if self.state not in {
            PersistentRuntimeState.NEW,
            PersistentRuntimeState.STOPPED,
            PersistentRuntimeState.CRASHED,
        }:
            raise RuntimeError(f"cannot start persistent runtime from {self.state.value}")
        self._verify_inputs()
        marker = self._marker_path()
        if marker.is_symlink():
            raise HarnessError(f"persistent runtime attestation is symlinked: {marker}")
        initialize = not marker.exists()
        if initialize and self.state is not PersistentRuntimeState.NEW:
            raise HarnessError("persistent runtime lost its initialization attestation")
        if not initialize:
            self._verify_attestation()
        self._prepare_workspace(new_workspace=initialize)
        self.workspace = self.persistent_workspace
        self.generation += 1
        self._allocate_ports()
        try:
            self._start_persistent_postgres(initialize=initialize)
            self._start_persistent_redis(initialize=initialize)
            maildir = self.persistent_workspace / "maildir"
            if initialize:
                install_maildir_fixture(self.paths.repository, maildir)
            elif maildir.is_symlink() or not maildir.is_dir():
                raise HarnessError("persistent Maildir is missing or symlinked")
            self._start_application()
            if initialize:
                self._write_attestation()
        except BaseException as error:
            self._record_start_failure(error)
            raise
        self.state = PersistentRuntimeState.RUNNING
        return self

    def restart_application(self) -> None:
        if self.state is not PersistentRuntimeState.RUNNING or self._application is None:
            raise RuntimeError("persistent application is not running")
        try:
            self._application.stop(
                timeout=self.shutdown_timeout,
                kill_timeout=self.shutdown_kill_timeout,
            )
        except BaseException:
            self.state = PersistentRuntimeState.CLEANUP_FAILED
            raise
        self._application = None
        self.generation += 1
        try:
            if self._port_allocator is None:
                raise RuntimeError("port allocator is not available")
            for port in self._application_service_ports():
                self._port_allocator.reserve_port(port)
            self._application_ports_released = False
            self._start_application()
        except BaseException as error:
            self._record_start_failure(error)
            raise

    def shutdown(self) -> None:
        if self.state is not PersistentRuntimeState.RUNNING:
            raise RuntimeError(f"cannot shut down persistent runtime from {self.state.value}")
        first_error: BaseException | None = None
        for attribute in ("_application", "_redis", "_postgres"):
            process = cast(ManagedProcess | None, getattr(self, attribute))
            if process is None:
                continue
            try:
                process.stop(
                    timeout=self.shutdown_timeout,
                    kill_timeout=self.shutdown_kill_timeout,
                )
            except BaseException as error:
                if first_error is None:
                    first_error = error
                else:
                    first_error.add_note(f"additional shutdown error: {error}")
            else:
                setattr(self, attribute, None)
        if first_error is not None:
            self.state = PersistentRuntimeState.CLEANUP_FAILED
            raise first_error
        self._release_ports()
        self.state = PersistentRuntimeState.STOPPED

    def crash(self) -> None:
        if self.state is not PersistentRuntimeState.RUNNING:
            raise RuntimeError(f"cannot crash persistent runtime from {self.state.value}")
        processes = tuple(
            process
            for process in (self._application, self._redis, self._postgres)
            if process is not None
        )
        try:
            kill_managed_processes(processes, kill_timeout=self.shutdown_kill_timeout)
        except BaseException:
            self.state = PersistentRuntimeState.CLEANUP_FAILED
            raise
        self._application = None
        self._redis = None
        self._postgres = None
        self._release_ports()
        self.state = PersistentRuntimeState.CRASHED

    def recover(self) -> Self:
        if self.state not in {
            PersistentRuntimeState.STOPPED,
            PersistentRuntimeState.CRASHED,
        }:
            raise RuntimeError(f"cannot recover persistent runtime from {self.state.value}")
        return self.start()

    def close(self) -> None:
        if self.state is PersistentRuntimeState.RUNNING:
            self.shutdown()
        elif self.state is PersistentRuntimeState.CLEANUP_FAILED:
            self._force_cleanup_after_start_failure()
        self._release_ports()
        self.ports = None
        self.state = PersistentRuntimeState.CLOSED

    def stop(self) -> None:
        if self.state is PersistentRuntimeState.RUNNING:
            self.shutdown()
        elif self.state is PersistentRuntimeState.CLEANUP_FAILED:
            self._force_cleanup_after_start_failure()
            self.state = PersistentRuntimeState.CRASHED

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.close()
