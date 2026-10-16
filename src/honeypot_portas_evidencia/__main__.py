"""Interface de linha de comando do honeypot."""

from __future__ import annotations

import argparse
import signal
import sys
import time

from .evidence import EvidenceLog
from .honeypot import Honeypot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeypot-portas-evidencia",
        description="Honeypot TCP que escuta portas falsas e grava evidência com hash SHA-256.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Endereço a vincular (padrão: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=2222,
        help="Porta falsa a escutar (padrão: 2222).",
    )
    parser.add_argument(
        "--log",
        default="evidence.log",
        help="Caminho do arquivo de evidência (padrão: evidence.log).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout de leitura por conexão, em segundos (padrão: 2.0).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    honeypot = Honeypot(host=args.host, port=args.port, timeout=args.timeout)
    log = EvidenceLog(args.log)

    stop_requested = False

    def handler(signum, frame) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    exit_code = 0
    try:
        port = honeypot.start()
        print(f"honeypot ouvindo em {args.host}:{port} (evidência: {args.log})")
        while not stop_requested and honeypot.listening:
            time.sleep(0.2)
    finally:
        honeypot.stop()
        for record in honeypot.records:
            log.append(record)
        print(f"{len(honeypot.records)} conexão(ões) registrada(s) em {args.log}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
