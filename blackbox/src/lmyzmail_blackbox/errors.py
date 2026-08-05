"""Typed harness failures with actionable process and protocol context."""


class HarnessError(RuntimeError):
    """Base class for deterministic harness failures."""


class ProcessStartError(HarnessError):
    """A supervised process exited before its readiness condition."""


class ProcessStopError(HarnessError):
    """A supervised process group could not be stopped within its deadline."""


class ProtocolError(HarnessError):
    """A peer violated a protocol or exceeded an explicit I/O budget."""


class GoldenMismatch(HarnessError):
    """Observed output differs from the immutable Java golden."""
