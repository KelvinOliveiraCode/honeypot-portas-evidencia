"""Honeypot TCP: escuta portas falsas e grava tentativas de conexão."""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from datetime import datetime, timezone

from .evidence import ConnectionRecord, compute_evidence_hash


class Honeypot:

    """Servidor TCP que simula portas abertas falsas.

    Cada conexão aceita é lida até o cliente fechar ou esgotar o
    timeout, e um registro com hash SHA-256 é armazenado em memória.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        timeout: float = 2.0,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._clock = clock or self._default_clock
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.records: list[ConnectionRecord] = []
        self._lock = threading.Lock()

    @staticmethod
    def _default_clock() -> str:
        return datetime.now(timezone.utc).isoformat()

    @property
    def listening(self) -> bool:
        """Retorna ``True`` enquanto o honeypot estiver aceitando conexões."""
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> int:
        """Liga o honeypot em uma thread e retorna a porta real vinculada."""
        if self.listening:
            raise RuntimeError("honeypot ja esta ouvindo")
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        actual_port = self._sock.getsockname()[1]
        self.port = actual_port
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return actual_port

    def stop(self, join_timeout: float = 5.0) -> None:
        """Para o honeypot e encerra a thread de aceitação."""
        self._stop.set()
        sock = self._sock
        if sock is not None:
            try:  # noqa: SIM105 — sem supressor de contexto disponível aqui
                sock.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=join_timeout)
        self._sock = None
        self._thread = None

    def _accept_loop(self) -> None:
        sock = self._sock
        if sock is None:
            return
        sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self._handle(conn, addr)

    def _handle(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        client_host, client_port = addr
        with conn:
            conn.settimeout(self.timeout)
            data = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except TimeoutError:
                pass
            except OSError:
                pass
        timestamp = self._clock()
        local_port = self._local_port()
        record = ConnectionRecord(
            timestamp=timestamp,
            client_host=client_host,
            client_port=client_port,
            local_port=local_port,
            data=data,
            evidence_hash=compute_evidence_hash(
                timestamp, client_host, client_port, local_port, data
            ),
        )
        with self._lock:
            self.records.append(record)

    def _local_port(self) -> int:
        sock = self._sock
        if sock is None:
            return 0
        try:
            return sock.getsockname()[1]
        except OSError:
            return 0

    def __enter__(self) -> Honeypot:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
