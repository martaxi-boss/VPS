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


## Atualização canónica — 29/10/2026: limpeza de processos ainda não estabilizada

**Estado atual de `cleanup_incomplete`: FAIL (reproduzido após correção parcial).** Os testes funcionais atuais revelaram `environment_errno_ESRCH` em tarefas Linux `kworker` com `PPID=2`, `PGID=0`, `PF_KTHREAD` e UID 0. Depois da correção compilada que passou a aceitar estado de kernel `R`, a captura com oito subprocessos passou três vezes e voltou a falhar no PID `225319`; o erro de limpeza ficou pendente. O serviço continua ativo.

- **Módulo instalado e verificado:** `ProcessOwnershipObservation.js`, SHA256 `05426e8e3f3c1b42a9ccaafee64ef562e5e587e3e15f8f68387d29b8b7237a06`.
- **Módulo de classificação ainda instalado:** `ProcessOwnership.js`, SHA256 `896032442deb6ee3aad314d5778e7310ff5598127a03d667387724085984cec6`.
- **Causa demonstrada em ensaio isolado:** sem o contexto opcional de relação, uma tarefa nativa do kernel com leitura ESRCH é considerada erro de propriedade; com relação explícita, é reconhecida como não pertencente à captura.
- **Novo corretivo apenas preparado, não instalado:** `rea-linux/install/rea_pf_kthread_relation_free_fix_20261029.py`. Passou os ensaios de aceitação kernel, rejeição de processo normal e rejeição de geração incorreta, mas a operação de instalação foi bloqueada pela segurança da plataforma; não foi tentada outra via para contornar esse bloqueio.
- **Relatório com IDs de evidência, falhas e estado da VPS:** [`process-capture-cleanup-investigation-20261029.json`](process-capture-cleanup-investigation-20261029.json).
- **GitHub Actions após a primeira correção:** [execução 40845383789](https://github.com/martaxi-boss/VPS/actions/runs/40845383789), sucesso de transporte; **não** prova a correção definitiva.
- **Certificações mantidas:** 170 testes positivos circunscritos ao âmbito documentado de 229 ferramentas; 59 pendentes. Sem certificações novas aprovadas a partir desta falha.

As pastas temporárias recentes relacionadas com limpeza não verificada permanecem preservadas. Um teste de três capturas MCP independentes em paralelo terminou sem resposta SSE; paralelismo de capturas permanece por certificar. Não reiniciar repetidamente nem apagar recursos retidos como substituto da correção de propriedade.
