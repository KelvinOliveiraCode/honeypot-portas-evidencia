# honeypot-portas-evidencia

## Português

### Descrição

Honeypot TCP de porta falsa escrito em Python com apenas a biblioteca padrão (`socket`, `hashlib`). Ele escuta uma porta configurada, aceita conexões de qualquer cliente, grava cada conexão em um arquivo de evidência (JSON-lines) e anexa a cada registro um hash SHA-256 calculado sobre carimbo de data/hora, endereço e porta do cliente, porta local e dados recebidos. O hash permite comprovar depois que o arquivo de evidência não foi adulterado.

### Como usar

Execução direta com Python (sem dependências externas):

```
python -m honeypot_portas_evidencia --port 2222 --log evidence.log
```

Opções:

- `--host`: endereço a vincular (padrão: `127.0.0.1`)
- `--port`: porta falsa a escutar (padrão: `2222`)
- `--log`: caminho do arquivo de evidência (padrão: `evidence.log`)
- `--timeout`: tempo de leitura por conexão, em segundos (padrão: `2.0`)

O honeypot roda até receber `Ctrl+C` (ou `SIGTERM`), quando grava os registros acumulados e encerra.

### Testes

A suíte é pytest e roda apenas com a biblioteca padrão do Python:

```
uv run pytest -q
```

Resultado: 12 aprovados em 0,29 s.

Os testes cobrem: determinismo do hash SHA-256, detecção de alteração em qualquer campo, gravação e leitura do arquivo de evidência, verificação de integridade (válido → passa; hash ou dados adulterados → falha), alocação de porta, captura de conexões reais em localhost, multiplas conexões e uso como gerenciador de contexto.

### Licença

MIT

### Autor

Kelvin Oliveira

---

## English

### Description

TCP honeypot with a fake open port, written in Python using only the standard library (`socket`, `hashlib`). It listens on a configured port, accepts connections from any client, records each connection in a JSON-lines evidence file, and attaches to every record a SHA-256 hash computed over the UTC timestamp, client address and port, local port, and received data. The hash makes it possible to prove later that the evidence file was not tampered with.

### How to use

Run directly with Python (no external dependencies):

```
python -m honeypot_portas_evidencia --port 2222 --log evidence.log
```

Options:

- `--host`: address to bind (default: `127.0.0.1`)
- `--port`: fake port to listen on (default: `2222`)
- `--log`: path to the evidence file (default: `evidence.log`)
- `--timeout`: read timeout per connection, in seconds (default: `2.0`)

The honeypot runs until `Ctrl+C` (or `SIGTERM`), at which point it flushes the accumulated records and exits.

### Tests

The suite is pytest and needs only the Python standard library:

```
uv run pytest -q
```

Result: 12 passed in 0.29 s.

Tests cover: SHA-256 hash determinism, detection of changes in any field, evidence file write and read, integrity verification (valid → passes; tampered hash or data → fails), port allocation, real connection capture on localhost, multiple connections, and context-manager usage.

### License

MIT

### Author

Kelvin Oliveira
