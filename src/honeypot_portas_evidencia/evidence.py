"""Integridade de evidência: hash SHA-256 de registros de conexão.

Cada registro de conexão capturado pelo honeypot recebe um hash
determinístico (SHA-256) que permite compromar a integridade do
arquivo de evidência a posteriori.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ConnectionRecord:

    """Registro imutável de uma conexão capturada pelo honeypot."""

    timestamp: str  # ISO 8601 UTC
    client_host: str
    client_port: int
    local_port: int
    data: bytes
    evidence_hash: str

    def to_dict(self) -> dict:
        """Serializa o registro para dicionário JSON-compatível."""
        payload = asdict(self)
        payload["data"] = self.data.decode("utf-8", errors="replace")
        return payload


def compute_evidence_hash(
    timestamp: str,
    client_host: str,
    client_port: int,
    local_port: int,
    data: bytes,
) -> str:
    """Calcula o hash SHA-256 determinístico de uma conexão.

    A ordem dos campos é fixa para garantir reprodutibilidade do hash
    independente de quem ou onde o cálculo é executado.
    """
    h = hashlib.sha256()
    h.update(b"honeypot-portas-evidencia|v1")
    h.update(b"|")
    h.update(timestamp.encode("utf-8"))
    h.update(b"|")
    h.update(client_host.encode("utf-8"))
    h.update(b"|")
    h.update(str(client_port).encode("ascii"))
    h.update(b"|")
    h.update(str(local_port).encode("ascii"))
    h.update(b"|")
    h.update(data)
    return h.hexdigest()


class EvidenceLog:

    """Acumula registros de conexão e persiste em arquivo JSON-lines.

    Cada linha escrita no disco já traz o respectivo hash de
    evidência, permitindo verificação posterior com :func:`verify_log`.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, record: ConnectionRecord) -> None:
        """Escreve um registro no arquivo de evidência."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record.to_dict(), ensure_ascii=False, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")

    def read(self) -> list[ConnectionRecord]:
        """Lê todos os registros gravados no arquivo."""
        if not self.path.exists():
            return []
        records: list[ConnectionRecord] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                payload["data"] = payload["data"].encode("utf-8")
                records.append(ConnectionRecord(**payload))  # type: ignore[arg-type]
        return records


def verify_log(path: str | Path) -> bool:
    """Verifica a integridade de um arquivo de evidência.

    Retorna ``True`` somente se cada registro tiver seu campo
    ``evidence_hash`` igual ao hash recalculado a partir dos demais
    campos.
    """
    log = EvidenceLog(path)
    records = log.read()
    for record in records:
        expected = compute_evidence_hash(
            record.timestamp,
            record.client_host,
            record.client_port,
            record.local_port,
            record.data,
        )
        if record.evidence_hash != expected:
            return False
    return True


def iter_records(path: str | Path) -> Iterable[ConnectionRecord]:
    """Itera sobre os registros de um arquivo de evidência."""
    return iter(EvidenceLog(path).read())
