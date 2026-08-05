from __future__ import annotations

import socket
import threading
from queue import Queue

import pytest

from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.protocols import encode_varint, minecraft_status


def _serve_status_packet(
    packet_payload: bytes,
) -> tuple[int, threading.Thread, Queue[BaseException]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    errors: Queue[BaseException] = Queue()

    def server() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                assert connection.recv(4096)
                connection.sendall(encode_varint(len(packet_payload)) + packet_payload)
        except BaseException as error:
            errors.put(error)
        finally:
            listener.close()

    thread = threading.Thread(target=server)
    thread.start()
    return port, thread, errors


def _status_payload(json_payload: bytes, *, trailing: bytes = b"") -> bytes:
    return b"\x00" + encode_varint(len(json_payload)) + json_payload + trailing


def test_minecraft_status_parses_one_strictly_bounded_packet() -> None:
    port, thread, errors = _serve_status_packet(_status_payload(b'{"ok":true}'))
    value = minecraft_status("127.0.0.1", port)
    thread.join(timeout=2.0)

    assert not thread.is_alive()
    if not errors.empty():
        raise errors.get()
    assert value == {"ok": True}


@pytest.mark.parametrize(
    ("json_payload", "trailing", "message"),
    [
        (b'{"ok":true}', b"x", "invalid Minecraft JSON length"),
        (b'{"number":NaN}', b"", "non-standard JSON constant"),
        (b'{"same":1,"same":2}', b"", "duplicate JSON object key"),
    ],
)
def test_minecraft_status_rejects_trailing_or_nonstandard_json(
    json_payload: bytes,
    trailing: bytes,
    message: str,
) -> None:
    port, thread, errors = _serve_status_packet(_status_payload(json_payload, trailing=trailing))
    with pytest.raises(ProtocolError, match=message):
        minecraft_status("127.0.0.1", port)
    thread.join(timeout=2.0)

    assert not thread.is_alive()
    if not errors.empty():
        raise errors.get()
