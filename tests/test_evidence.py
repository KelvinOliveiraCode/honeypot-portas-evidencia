"""Testes do módulo de integridade de evidência (hash SHA-256)."""

from __future__ import annotations

import json
from pathlib import Path

from honeypot_portas_evidencia import (
    ConnectionRecord,
    compute_evidence_hash,
    verify_log,
)

FIXED_TS = "2024-01-01T00:00:00+00:00"


def test_compute_evidence_hash_eh_deterministico() -> None:
    """Mesmos inputs devem produzir sempre o mesmo hash."""
    h1 = compute_evidence_hash(
        FIXED_TS, "127.0.0.1", 54321, 2222, b"probe"
    )
    h2 = compute_evidence_hash(
        FIXED_TS, "127.0.0.1", 54321, 2222, b"probe"
    )
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_compute_evidence_hash_muda_se_os_dados_mudam() -> None:
    """Qualquer mudança de campo deve alterar o hash (avalanche simples)."""
    base = compute_evidence_hash(
        FIXED_TS, "127.0.0.1", 54321, 2222, b"probe"
    )
    assert base != compute_evidence_hash(
        FIXED_TS, "127.0.0.1", 54321, 2222, b"probe2"
    )
    assert base != compute_evidence_hash(
        FIXED_TS, "127.0.0.1", 54321, 9999, b"probe"
    )
    assert base != compute_evidence_hash(
        FIXED_TS, "10.0.0.1", 54321, 2222, b"probe"
    )
    assert base != compute_evidence_hash(
        "2024-01-02T00:00:00+00:00", "127.0.0.1", 54321, 2222, b"probe"
    )


def test_connection_record_to_dict_contem_hash() -> None:
    """O dicionário serializado deve preservar o campo de hash."""
    record = ConnectionRecord(
        timestamp=FIXED_TS,
        client_host="127.0.0.1",
        client_port=54321,
        local_port=2222,
        data=b"x",
        evidence_hash="abc",
    )
    payload = record.to_dict()
    assert payload["evidence_hash"] == "abc"
    assert payload["data"] == "x"


def test_verify_log_retorna_true_para_log_valido(tmp_path: Path) -> None:
    """Arquivo gravado com registros válidos passa na verificação."""
    log_file = tmp_path / "evidence.log"
    records = [
        ConnectionRecord(
            timestamp=FIXED_TS,
            client_host="127.0.0.1",
            client_port=1000,
            local_port=2222,
            data=b"uno",
            evidence_hash=compute_evidence_hash(
                FIXED_TS, "127.0.0.1", 1000, 2222, b"uno"
            ),
        ),
        ConnectionRecord(
            timestamp=FIXED_TS,
            client_host="127.0.0.1",
            client_port=1001,
            local_port=2222,
            data=b"dos",
            evidence_hash=compute_evidence_hash(
                FIXED_TS, "127.0.0.1", 1001, 2222, b"dos"
            ),
        ),
    ]
    with log_file.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record.to_dict(), ensure_ascii=False))
            fh.write("\n")

    assert verify_log(log_file) is True


def test_verify_log_retorna_false_apos_adulterar_hash(tmp_path: Path) -> None:
    """Alterar o evidence_hash de uma linha deve invalidadar o log."""
    log_file = tmp_path / "evidence.log"
    record = ConnectionRecord(
        timestamp=FIXED_TS,
        client_host="127.0.0.1",
        client_port=1000,
        local_port=2222,
        data=b"uno",
        evidence_hash=compute_evidence_hash(
            FIXED_TS, "127.0.0.1", 1000, 2222, b"uno"
        ),
    )
    with log_file.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(record.to_dict(), ensure_ascii=False))
        fh.write("\n")

    assert verify_log(log_file) is True

    # Adulteração: troca o hash por um valor inválido.
    linhas = log_file.read_text(encoding="utf-8").splitlines()
    payload = json.loads(linhas[0])
    payload["evidence_hash"] = "0" * 64
    log_file.write_text("\n".join([json.dumps(payload)]) + "\n", encoding="utf-8")

    assert verify_log(log_file) is False


def test_verify_log_retorna_false_apos_adulterar_dados(tmp_path: Path) -> None:
    """Alterar os dados da conexão sem recalcular o hash deve invalidadar."""
    log_file = tmp_path / "evidence.log"
    record = ConnectionRecord(
        timestamp=FIXED_TS,
        client_host="127.0.0.1",
        client_port=1000,
        local_port=2222,
        data=b"uno",
        evidence_hash=compute_evidence_hash(
            FIXED_TS, "127.0.0.1", 1000, 2222, b"uno"
        ),
    )
    with log_file.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(record.to_dict(), ensure_ascii=False))
        fh.write("\n")

    linhas = log_file.read_text(encoding="utf-8").splitlines()
    payload = json.loads(linhas[0])
    payload["data"] = "alterado"
    log_file.write_text("\n".join([json.dumps(payload)]) + "\n", encoding="utf-8")

    assert verify_log(log_file) is False
