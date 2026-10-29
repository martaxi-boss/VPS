# REA original — Unblob existente operacional via GitHub Actions (29 outubro 2026)

## Resultado certificado no ambiente testado

**PASS** — Unblob 26.6.4, já instalado em `/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob`, agora é executável pelo utilizador `ubuntu`, sem instalação, sem nova ponte MCP, sem iniciar o antigo serviço e sem alterar o código original REA.

- **Primeira prova completa:** [GitHub Actions run 40927237784, tentativa 1](https://github.com/martaxi-boss/VPS/actions/runs/40927237784/attempts/1), job `123635890699` — SUCCESS.
- **Prova de persistência com nova sessão SSH, sem nova mudança de ACL:** [GitHub Actions run 40927237784, tentativa 2](https://github.com/martaxi-boss/VPS/actions/runs/40927237784/attempts/2), job `123636609805` — SUCCESS.
- Script do ensaio/reparação idempotente: `rea-linux/tests/rea_original_unblob_access_fix_20261029.py`.
- Workflow SSH existente: `.github/workflows/rea-mcp-transport-20261027.yml` (nome de ficheiro legado; execução real usa **somente** GitHub Actions → SSH → REA CLI).
- Código REA oficial intacto: `morluto/rea` tag `rea-agents-6.8.0`, commit `160d821ac9a0310afcb8d1fc427862dd6508add5`.
- Evidências de cada comando, saída, ACL antes/depois e ficheiro extraído: `/home/ubuntu/rea-original-upstream-680-evidence/unblob-existing-20261029` (VPS, acesso do proprietário).

## Causa e correção mínima

**Causa comprovada:** diretório existente `/opt/rea-reversa/providers/unblob-26.6.4` pertence ao UID 994 e tinha modo `0750`. O SSH como `ubuntu` não conseguia atravessá-lo, recebendo `PermissionError / EACCES` ao iniciar o fornecedor. O motor antigo tinha outro utilizador de execução, daí a diferença de acesso.

**Alteração efetivamente realizada:** aplicação de ACL POSIX limitada ao **único diretório raiz do fornecedor existente**, para conceder apenas o direito de travessia a `ubuntu`:

```sh
sudo -n setfacl -m u:ubuntu:--x /opt/rea-reversa/providers/unblob-26.6.4
```

Não houve `chmod 777`, `chown`, alteração de grupo, instalação, mudança de serviços, reboot, nova chave SSH nem mudança do endpoint MCP antigo. O teste preparou `REA_UNBLOB_COMMAND` por invocação CLI do original. A alteração ACL foi verificada por leitura; a segunda execução começou com acesso **PASS**, sem a reaplicar.

## Testes reais

| Verificação | Tentativa 1 | Tentativa 2 |
|---|---|---|
| Original oficial e módulos compilados com digest esperado | PASS | PASS |
| Dependências Node anteriormente existentes, sem reinstalar | PASS | PASS |
| `unblob --version` = `26.6.4` | PASS | PASS |
| `prlimit` e `7z` disponíveis | PASS | PASS |
| `rea extract-firmware` em gzip + TAR controlado, sem simulação de fornecedor | PASS | PASS |
| Identificação de chunk `gzip` real | PASS | PASS |
| Ficheiro efetivamente extraído e SHA-256 comparado com referência independente | PASS | PASS |
| Captura original de 8 subprocessos e limpeza verificada | PASS | PASS |
| Captura original de 30 subprocessos e limpeza verificada | PASS | PASS |
| `cleanup_incomplete` | 0 | 0 |
| Ligação MCP antiga utilizada | NÃO | NÃO |
| Pacotes externos instalados | 0 | 0 |

Os dados são uma certificação **do fluxo de firmware e dos cenários testados**, não de todas as extensões possíveis do Unblob nem de todas as operações do catálogo do motor.

## Decisão para a próxima etapa

A utilização do Unblob no original deve passar através do **mesmo GitHub Actions → SSH**, com a variável de ambiente por invocação:

```sh
REA_UNBLOB_COMMAND=/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob
```

Não criar nova ponte MCP para usar o fornecedor. A permissão existente para `ubuntu` mantém o acesso enquanto a ACL não for alterada. O serviço antigo não foi removido; tal remoção seria uma operação distinta.
