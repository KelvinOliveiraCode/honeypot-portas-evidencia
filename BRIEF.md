# BRIEF — honeypot-portas-evidencia

**Área:** Cibersegurança  
**Projeto:** honeypot + integridade de evidência  
**Local:** `C:\Users\Kelvin\AppData\Local\Temp\opencode\github-staging\projects\honeypot-portas-evidencia\`  
**Autor:** Kelvin Oliveira  
**Validação:** workflow manager (este subagent)

## O que foi entregue

| Arquivo | Conteúdo |
|---------|----------|
| `pyproject.toml` | Projeto Python (setuptools, src layout), entry point `honeypot-portas-evidencia`, dep de teste `pytest>=8`, config do ruff |
| `src/honeypot_portas_evidencia/__init__.py` | Export público da API |
| `src/honeypot_portas_evidencia/honeypot.py` | `Honeypot`: escuta porta falsa TCP, aceita conexões, grava `ConnectionRecord` (timestamp UTC, cliente, porta local, dados, hash SHA-256) |
| `src/honeypot_portas_evidencia/evidence.py` | `compute_evidence_hash` (SHA-256 determinístico), `EvidenceLog` (JSON-lines), `verify_log` (integridade), `ConnectionRecord` |
| `src/honeypot_portas_evidencia/__main__.py` | CLI: `--host`, `--port`, `--log`, `--timeout`; roda até `Ctrl+C`/`SIGTERM` |
| `tests/conftest.py` | Coloca `src/` no `sys.path` |
| `tests/test_evidence.py` | Hash, determinismo, adulteração de hash/dados |
| `tests/test_honeypot.py` | Porta alocada, captura de conexões reais, múltiplas conexões, gerenciador de contexto |
| `README.md` | Bilíngue PT-BR + EN: descrição, como usar, testes, licença MIT, autor |
| `BRIEF.md` | Este arquivo |

## Critérios de aceitação (PLANO_50_PROJETOS.md)

- [x] Stack Python + `socket` + `hashlib` (somente stdlib)
- [x] Escuta portas falsas e grava conexões
- [x] Logs com hash SHA-256 de evidência
- [x] Suíte pytest que passa (12 aprovados)
- [x] README PT-BR + EN completo

## Como verificar

No diretório do projeto:

```
uv run --with ruff ruff check .
uv run pytest -q
```

Resultado esperado: `All checks passed!` e `12 passed in 0.29 s`.

Para testar o honeypot na prática:

```
python -m honeypot_portas_evidencia --port 2222 --log evidence.log
# em outro terminal:
python -c "import socket; s=socket.create_connection(('127.0.0.1',2222),1); s.sendall(b'probe'); s.close()"
# Ctrl+C no honeypot, então:
python -c "from honeypot_portas_evidencia import verify_log; print(verify_log('evidence.log'))"  # deve imprimir True
```

Caminhos: `README.md` e `BRIEF.md` na raiz do projeto acima.
