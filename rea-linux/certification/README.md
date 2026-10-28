# REA 6.8.0 — Operação e certificações (estado atual)

**Versão operacional única:** REA 6.8.0, em `/opt/rea-reversa/rea`. O código-fonte original está no repositório `martaxi-boss/Engenheira-reversa`, pasta `rea/`, sem alterações.

**Certificações reais:** 159/229 ferramentas, aprovadas apenas nos cenários testados; 70 por certificar. Nunca marcar uma ferramenta a verde sem prova positiva e negativa aplicável, oráculo independente e confirmação do ambiente.

- [Índice atual e individual de 229 ferramentas](rea-6.8.0-current-certifications.json).
- [Registo consolidado com as 159 certificações e respetivas provas](functional-ledger.json).
- [Último lote que concluiu as primeiras 150](priority4-target150-batch-f-final-20261028.json).
- [Estado resumido](STATUS_6_8_0.md).
- [Índice no repositório principal do projeto](https://github.com/martaxi-boss/Engenheira-reversa/blob/main/certifications/rea-6.8.0.json).

**Transporte operacional existente:** ChatGPT → GitHub Actions → SSH → VPS Linux → REA MCP original. Workflow: `.github/workflows/rea-mcp-transport-20261027.yml`, ramo `rea/one-skill-bridge-20261023`. A última execução positiva confirmada é [40788613330](https://github.com/martaxi-boss/VPS/actions/runs/40788613330), num commit anterior às atualizações documentais; não é certificação de cada ferramenta.

**Regras de continuidade:** ler sempre o índice atual em vez de assumir números de relatórios históricos. Não criar outro motor, Skill, MCP, ponte ou workflow. Não utilizar Codex. Não tocar em outros projetos. Não alterar código do motor original. Não executar fornecedores pagos sem fornecedor disponível nem ferramentas incompatíveis com Linux. Preservar provas, não repetir casos já certificados, e corrigir falhas reais antes de certificar operações dependentes.

**Último teste real (28/10/2026):** foi identificado um falso bloqueio de pertença envolvendo três tarefas do kernel Linux. Reiniciou-se apenas o serviço REA pelo workflow existente ([run 40788362758](https://github.com/martaxi-boss/VPS/actions/runs/40788362758)). Quatro capturas reais subsequentes passaram, com grupo de processos verificado e pastas temporárias removidas. A execução SSH com dois comandos objdump também passou ([run 40787663359](https://github.com/martaxi-boss/VPS/actions/runs/40787663359)). Este resultado é válido para os cenários testados; não certifica ausência de corridas futuras. Provas completas em [relatório de limpeza](process-kworker-cleanup-fix-live-pass-20261028.json).

**Nova ferramenta certificada:** `close_binary` (âmbito: sessão ELF64 aberta pelo Ghidra; fecho, reentrada idempotente, sem snapshot; ver [prova](priority5-close-binary-scoped-20261028.json)). Contagem atual: 159/229, pendentes: 78.

**Certificação em lote:** oito operações Frida e Wakaru com testes reais, provas e limitações [neste relatório](priority7-frida-wakaru-batch-20261028.json). Estado: 159/229, 70 pendentes. As certificações são circunscritas ao ambiente de ensaio.
