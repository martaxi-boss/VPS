# REA 6.8.0 — certificações

**170/229 ferramentas com testes funcionais positivos limitados ao âmbito documentado; 59 pendentes.**

- [Índice por ferramenta](rea-6.8.0-current-certifications.json)
- [Ledger funcional](functional-ledger.json)
- [Novo lote Chrome CDP: seis operações](priority11-chrome-cdp-20261029.json)
- [Lote Node.js e recuperação](priority10-node-runtime-cleanup-20261029.json)

O laboratório Chrome de teste foi encerrado: endpoint de depuração indisponível e ficheiro de teste ausente. A captura de processo usada na limpeza comunicou `cleanup_incomplete` por uma leitura ESRCH; não significa que a verificação interna desse mecanismo esteja resolvida permanentemente. Sem Android e sem fornecedores pagos. O código original permanece intacto.

## Diagnóstico de cleanup_incomplete (29/10/2026)

- O erro reapareceu na verificação de limpeza de uma captura, com `environment_errno_ESRCH` no PID 216468. Não foi confundido com prova de que esse processo pertencia à captura.
- O diagnóstico nativo Linux em [GitHub Actions 40799963933](https://github.com/martaxi-boss/VPS/actions/runs/40799963933) confirmou várias tarefas do kernel com `PPID=2`, `PGID=0`, estado `I`, marcador `PF_KTHREAD` e leitura do ambiente recusada.
- A hipótese de correção segura é reconhecer exclusivamente tarefas do kernel com identidade e geração nativas verificadas, preservando a falha fechada para processos normais e evitando sinais a terceiros. Esta hipótese **não está aplicada nem certificada**.
- As tentativas de instalação [40800380597](https://github.com/martaxi-boss/VPS/actions/runs/40800380597) e [40800484086](https://github.com/martaxi-boss/VPS/actions/runs/40800484086) falharam antes de aplicar a correção, e uma alteração posterior foi bloqueada pela verificação de segurança da plataforma.
- O transporte original foi restaurado exatamente e passou [GitHub Actions 40800632269](https://github.com/martaxi-boss/VPS/actions/runs/40800632269). O rascunho não aplicado foi removido. REA 6.8.0 mantém o catálogo de 229 ferramentas; contagem de certificações não alterada: 170 positivas no âmbito documentado e 59 pendentes.

**Estado: problema recorrente diagnosticado, mas não definitivamente corrigido.** Não repetir reinícios como substituto de uma correção validada do algoritmo de pertença.
