# REA 6.8.0 — Operação e certificações (estado atual)

**Versão operacional única:** REA 6.8.0, em `/opt/rea-reversa/rea`. O código-fonte original está no repositório `martaxi-boss/Engenheira-reversa`, pasta `rea/`, sem alterações.

**Certificações reais:** 150/229 ferramentas, aprovadas apenas nos cenários testados; 79 por certificar. Nunca marcar uma ferramenta a verde sem prova positiva e negativa aplicável, oráculo independente e confirmação do ambiente.

- [Índice atual e individual de 229 ferramentas](rea-6.8.0-current-certifications.json).
- [Registo consolidado com as 150 certificações e respetivas provas](functional-ledger.json).
- [Último lote que concluiu as 150](priority4-target150-batch-f-final-20261028.json).
- [Estado resumido](STATUS_6_8_0.md).
- [Índice no repositório principal do projeto](https://github.com/martaxi-boss/Engenheira-reversa/blob/main/certifications/rea-6.8.0.json).

**Transporte operacional existente:** ChatGPT → GitHub Actions → SSH → VPS Linux → REA MCP original. Workflow: `.github/workflows/rea-mcp-transport-20261027.yml`, ramo `rea/one-skill-bridge-20261023`. A última execução positiva confirmada é [40783514393](https://github.com/martaxi-boss/VPS/actions/runs/40783514393), num commit anterior às atualizações documentais; não é certificação de cada ferramenta.

**Regras de continuidade:** ler sempre o índice atual em vez de assumir números de relatórios históricos. Não criar outro motor, Skill, MCP, ponte ou workflow. Não utilizar Codex. Não tocar em outros projetos. Não alterar código do motor original. Não executar fornecedores pagos sem fornecedor disponível nem ferramentas incompatíveis com Linux. Preservar provas, não repetir casos já certificados, e corrigir falhas reais antes de certificar operações dependentes.

**Bloqueio conhecido a recuperar:** `capture_process_scenario` por vezes devolve `cleanup_incomplete` quando o token de pertença de processos transitórios devolve `environment_errno_ESRCH`. Uma execução anterior passou após correção de classificação de `kworker`, mas não certifica todas as corridas. A falha deve ser corrigida e validada sem suprimir erros, ignorar processos ou eliminar diretórios que possam estar ativos.
