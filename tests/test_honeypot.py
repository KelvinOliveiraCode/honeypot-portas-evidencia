"""Testes de comportamento do honeypot TCP (conexões reais em localhost)."""

from __future__ import annotations

import socket
import time

from honeypot_portas_evidencia import (
    ConnectionRecord,
    Honeypot,
    compute_evidence_hash,
)

FIXED_TS = "2024-01-01T00:00:00+00:00"


def _aguarda_registro(honeypot: Honeypot, timeout: float = 5.0) -> ConnectionRecord:
    """Espera aparecer ao menos um registro (polling, sem sono cego longo)."""
    prazo = time.time() + timeout
    while time.time() < prazo:
        with honeypot._lock:
            if honeypot.records:
                return honeypot.records[0]
        time.sleep(0.05)
    raise AssertionError("sem registro capturado")


def test_honeypot_aloca_porta_quando_zero() -> None:
    """port=0 deve resultar em uma porta efetiva alocada pelo SO."""
    honeypot = Honeypot(port=0, clock=lambda: FIXED_TS)
    try:
        porta = honeypot.start()
        assert porta > 0
        assert honeypot.port == porta
        assert honeypot.listening is True
    finally:
        honeypot.stop()


def test_honeypot_nao_esta_ouvindo_antes_de_iniciar() -> None:
    honeypot = Honeypot(port=0)
    assert honeypot.listening is False


def test_honeypot_captura_conexao_com_dados() -> None:
    """Um cliente real que se conecta e envia dados deve gerar registro."""
    honeypot = Honeypot(port=0, clock=lambda: FIXED_TS, timeout=0.5)
    try:
        porta = honeypot.start()

        cliente = socket.create_connection(("127.0.0.1", porta), timeout=1.0)
        try:
            cliente.sendall(b"comando-falso")
        finally:
            cliente.close()

        registro = _aguarda_registro(honeypot)
    finally:
        honeypot.stop()

    assert registro.client_host == "127.0.0.1"
    assert registro.client_port > 0
    assert registro.local_port == porta
    assert registro.data == b"comando-falso"
    assert registro.timestamp == FIXED_TS
    assert registro.evidence_hash == compute_evidence_hash(
        FIXED_TS, "127.0.0.1", registro.client_port, porta, b"comando-falso"
    )


def test_honeypot_captura_multiplas_conexoes() -> None:
    honeypot = Honeypot(port=0, clock=lambda: FIXED_TS, timeout=0.5)
    try:
        porta = honeypot.start()
        for i in range(3):
            cliente = socket.create_connection(("127.0.0.1", porta), timeout=1.0)
            cliente.sendall(f"msg-{i}".encode())
            cliente.close()

        prazo = time.time() + 5.0
        while time.time() < prazo:
            with honeypot._lock:
                if len(honeypot.records) >= 3:
                    break
            time.sleep(0.05)
    finally:
        honeypot.stop()

    assert len(honeypot.records) == 3
    dados = {r.data for r in honeypot.records}
    assert dados == {b"msg-0", b"msg-1", b"msg-2"}
    for registro in honeypot.records:
        assert registro.evidence_hash == compute_evidence_hash(
            FIXED_TS,
            registro.client_host,
            registro.client_port,
            registro.local_port,
            registro.data,
        )


def test_honeypot_contexto_gerente_para_ao_sair() -> None:
    honeypot = Honeypot(port=0, clock=lambda: FIXED_TS)
    with honeypot:
        porta = honeypot.port
        assert porta > 0
        assert honeypot.listening is True
    assert honeypot.listening is False
    # A porta não deve ficar bloqueada: um novo honeypot consegue ligar nela.
    outro = Honeypot(port=porta, clock=lambda: FIXED_TS)
    try:
        outro.start()
        assert outro.listening is True
    finally:
        outro.stop()


def test_stop_sem_start_nao_quebra() -> None:
    honeypot = Honeypot(port=0)
    honeypot.stop()  # deve retornar sem exceção
    assert honeypot.listening is False
