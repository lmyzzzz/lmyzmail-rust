from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, cast

import redis
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from .errors import HarnessError

_MAX_MAIL_FILE_BYTES = 8 * 1024 * 1024
_MAX_MAILDIR_BYTES = 64 * 1024 * 1024
_MAX_REDIS_KEYS = 1024


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MaildirFile(_StrictModel):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0, le=_MAX_MAIL_FILE_BYTES)
    subdirectory: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_path_contract(self) -> MaildirFile:
        relative = PurePosixPath(self.path)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("maildir fixture path must be a contained relative path")
        if len(relative.parts) not in {3, 4} or relative.suffix != ".eml":
            raise ValueError("maildir fixture path does not match the legacy layout")
        expected = 0 if len(relative.parts) == 3 else int(relative.parts[-2])
        if expected != self.subdirectory or (len(relative.parts) == 4 and expected <= 0):
            raise ValueError("maildir fixture subdirectory does not match its path")
        return self


class MaildirFixture(_StrictModel):
    schema_version: Literal[1]
    files: tuple[MaildirFile, ...]
    total_bytes: int = Field(ge=0, le=_MAX_MAILDIR_BYTES)

    @model_validator(mode="after")
    def validate_totals(self) -> MaildirFixture:
        paths = [entry.path for entry in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("maildir fixture paths must be unique")
        if sum(entry.size for entry in self.files) != self.total_bytes:
            raise ValueError("maildir fixture total_bytes does not match file sizes")
        return self


class RedisStringSeed(_StrictModel):
    type: Literal["string"]
    key: str
    ttl_seconds: int | None = Field(default=None, gt=0, le=604800)
    value: JsonValue
    value_encoding: Literal["json-compact"] | None = None

    @model_validator(mode="after")
    def validate_encoding(self) -> RedisStringSeed:
        if self.value_encoding is None and not isinstance(self.value, str):
            raise ValueError("plain Redis string seed values must be strings")
        return self


class RedisHashSeed(_StrictModel):
    type: Literal["hash"]
    key: str
    ttl_seconds: int | None = Field(default=None, gt=0, le=604800)
    fields: dict[str, JsonValue]
    field_encoding: Literal["json-compact"] | None = None

    @model_validator(mode="after")
    def validate_fields(self) -> RedisHashSeed:
        if not self.fields:
            raise ValueError("Redis hash seed must contain at least one field")
        if self.field_encoding is None and not all(
            isinstance(value, str) for value in self.fields.values()
        ):
            raise ValueError("plain Redis hash seed values must be strings")
        return self


class RedisZsetMember(_StrictModel):
    member: str
    score: int | float


class RedisZsetSeed(_StrictModel):
    type: Literal["zset"]
    key: str
    ttl_seconds: int | None = Field(default=None, gt=0, le=604800)
    members: tuple[RedisZsetMember, ...]

    @model_validator(mode="after")
    def validate_members(self) -> RedisZsetSeed:
        members = [entry.member for entry in self.members]
        if not members or len(members) != len(set(members)):
            raise ValueError("Redis zset seed members must be non-empty and unique")
        return self


RedisSeedEntry = Annotated[
    RedisStringSeed | RedisHashSeed | RedisZsetSeed,
    Field(discriminator="type"),
]


class RedisSeedFixture(_StrictModel):
    schema_version: Literal[1]
    database: Literal[0]
    keys: tuple[RedisSeedEntry, ...]

    @model_validator(mode="after")
    def validate_keys(self) -> RedisSeedFixture:
        if len(self.keys) > _MAX_REDIS_KEYS:
            raise ValueError("Redis seed exceeds the key budget")
        keys = [entry.key for entry in self.keys]
        if len(keys) != len(set(keys)):
            raise ValueError("Redis seed keys must be unique")
        for key in keys:
            encoded = key.encode("utf-8")
            if not encoded or len(encoded) > 512 or b"\x00" in encoded or b"\r" in encoded:
                raise ValueError(f"invalid Redis seed key: {key!r}")
        return self


def _load_model(path: Path, model: type[_StrictModel]) -> _StrictModel:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return model.model_validate(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
        raise HarnessError(f"invalid legacy fixture {path}: {error}") from error


def load_maildir_fixture(repository: Path) -> MaildirFixture:
    path = repository / "blackbox/fixtures/legacy/maildir.json"
    return cast(MaildirFixture, _load_model(path, MaildirFixture))


def load_redis_seed(repository: Path) -> RedisSeedFixture:
    path = repository / "blackbox/fixtures/legacy/redis-seed.json"
    return cast(RedisSeedFixture, _load_model(path, RedisSeedFixture))


def _maildir_source(repository: Path, relative: str) -> Path:
    root = repository / "blackbox/fixtures/legacy/maildir"
    path = root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink() or not path.is_file():
        raise HarnessError(f"maildir fixture file is missing or symlinked: {path}")
    current = path.parent
    while current != root:
        if current.is_symlink() or not current.is_dir():
            raise HarnessError(f"maildir fixture parent is invalid: {current}")
        current = current.parent
    return path


def verify_maildir_fixture(repository: Path) -> MaildirFixture:
    fixture = load_maildir_fixture(repository)
    root = repository / "blackbox/fixtures/legacy/maildir"
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise HarnessError(f"symlink is forbidden in maildir fixture: {path}")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    expected = {entry.path for entry in fixture.files}
    if actual != expected:
        raise HarnessError(
            f"maildir fixture file set changed: actual={sorted(actual)!r}, "
            f"expected={sorted(expected)!r}"
        )
    for entry in fixture.files:
        path = _maildir_source(repository, entry.path)
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        value = path.read_bytes()
        if len(value) != entry.size or digest != entry.sha256:
            raise HarnessError(f"maildir fixture hash or size mismatch: {entry.path}")
        if not value.endswith(b"\r\n") or b"\n" in value.replace(b"\r\n", b""):
            raise HarnessError(f"maildir fixture does not use strict CRLF: {entry.path}")
    return fixture


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_maildir_fixture(repository: Path, target: Path) -> MaildirFixture:
    fixture = verify_maildir_fixture(repository)
    if target.is_symlink():
        raise HarnessError(f"maildir target may not be a symlink: {target}")
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target, 0o700)
    if any(target.iterdir()):
        raise HarnessError(f"maildir target is not empty: {target}")

    for entry in fixture.files:
        source = _maildir_source(repository, entry.path)
        destination = target.joinpath(*PurePosixPath(entry.path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(destination.parent, 0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            os.chmod(temporary, 0o600)
            with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
                shutil.copyfileobj(input_stream, output_stream, length=64 * 1024)
                output_stream.flush()
                os.fsync(output_stream.fileno())
            with temporary.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if temporary.stat().st_size != entry.size or digest != entry.sha256:
                raise HarnessError(f"maildir fixture copy changed bytes: {entry.path}")
            os.replace(temporary, destination)
            _fsync_directory(destination.parent)
        finally:
            temporary.unlink(missing_ok=True)
    _fsync_directory(target)
    return fixture


def _json_bytes(value: JsonValue) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _seed_bytes(value: JsonValue, encoding: str | None) -> bytes:
    if encoding == "json-compact":
        return _json_bytes(value)
    if not isinstance(value, str):
        raise AssertionError("validated plain seed value was not a string")
    return value.encode("utf-8")


def apply_redis_seed(
    client: redis.Redis,
    fixture: RedisSeedFixture,
) -> None:
    existing = [entry.key for entry in fixture.keys if client.exists(entry.key)]
    if existing:
        raise HarnessError(f"refusing to overwrite Redis fixture keys: {existing!r}")
    pipeline = client.pipeline(transaction=True)
    for entry in fixture.keys:
        if isinstance(entry, RedisStringSeed):
            pipeline.set(
                entry.key,
                _seed_bytes(entry.value, entry.value_encoding),
                ex=entry.ttl_seconds,
            )
        elif isinstance(entry, RedisHashSeed):
            mapping = {
                key.encode("utf-8"): _seed_bytes(value, entry.field_encoding)
                for key, value in entry.fields.items()
            }
            pipeline.hset(entry.key, mapping=mapping)
            if entry.ttl_seconds is not None:
                pipeline.expire(entry.key, entry.ttl_seconds)
        else:
            pipeline.zadd(
                entry.key,
                {member.member: float(member.score) for member in entry.members},
            )
            if entry.ttl_seconds is not None:
                pipeline.expire(entry.key, entry.ttl_seconds)
    pipeline.execute()


def snapshot_redis_seed(
    client: redis.Redis,
    fixture: RedisSeedFixture,
    *,
    ttl_drift_ms: int = 5000,
) -> list[dict[str, JsonValue]]:
    observations: list[dict[str, JsonValue]] = []
    for entry in fixture.keys:
        actual_type = client.type(entry.key)
        expected_type = entry.type.encode("ascii")
        if actual_type != expected_type:
            raise HarnessError(
                f"Redis key type mismatch for {entry.key}: {actual_type!r} != {expected_type!r}"
            )
        ttl_ms = cast(int, client.pttl(entry.key))
        if entry.ttl_seconds is None:
            if ttl_ms != -1:
                raise HarnessError(f"Redis key unexpectedly expires: {entry.key}={ttl_ms}")
        else:
            upper = entry.ttl_seconds * 1000
            if not upper - ttl_drift_ms <= ttl_ms <= upper:
                raise HarnessError(
                    f"Redis TTL drift for {entry.key}: {ttl_ms} not in "
                    f"[{upper - ttl_drift_ms}, {upper}]"
                )

        if isinstance(entry, RedisStringSeed):
            raw_value = client.get(entry.key)
            if raw_value != _seed_bytes(entry.value, entry.value_encoding):
                raise HarnessError(f"Redis string value mismatch: {entry.key}")
            cardinality = 1
        elif isinstance(entry, RedisHashSeed):
            expected_fields = {
                key.encode("utf-8"): _seed_bytes(value, entry.field_encoding)
                for key, value in entry.fields.items()
            }
            if client.hgetall(entry.key) != expected_fields:
                raise HarnessError(f"Redis hash value mismatch: {entry.key}")
            cardinality = len(expected_fields)
        else:
            expected_members = {
                member.member.encode("utf-8"): float(member.score) for member in entry.members
            }
            raw_members = cast(
                list[tuple[bytes, float]],
                client.zrange(entry.key, 0, -1, withscores=True),
            )
            actual_members = dict(raw_members)
            if actual_members != expected_members:
                raise HarnessError(f"Redis zset value mismatch: {entry.key}")
            cardinality = len(expected_members)
        observations.append(
            {
                "key": entry.key,
                "type": entry.type,
                "ttl_seconds": entry.ttl_seconds,
                "cardinality": cardinality,
            }
        )
    return observations
