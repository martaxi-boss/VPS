# VPS

Private operations repository for controlled VPS maintenance.

Para executar o Codex autonomamente, consulte as [instruções](ops/CODEX-AUTONOMOUS-SETUP.md).

## Certificação REA em curso (ramo `rea/one-skill-bridge-20261023`)

Para retomar a certificação do motor REA após mudar de conversa (incluindo ChatGPT Windows), consultar primeiro [o registo canónico e o método estável de recuperação de GitHub Actions `push`](rea-linux/certification/README.md#recuperação-canónica-de-github-actions-após-mudar-de-conversa-push) e [o ledger funcional](rea-linux/certification/functional-ledger.json). O wrapper `fetch_commit_workflow_runs` não é uma fonte válida para os runs `push` deste workflow; usar `mcp__GitHub__fetch` na REST API descrita na documentação, sem criar novos motores, pontes ou plugins. As instruções deste ramo não alteram os outros projetos.
