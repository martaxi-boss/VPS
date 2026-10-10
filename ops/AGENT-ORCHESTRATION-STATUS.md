# Orquestracao de agentes: estado e contrato de comandos

## Conectado e testado
- ChatGPT cria uma Issue no GitHub `martaxi-boss/VPS`.
- GitHub Actions encaminha auditorias `[codex audit]` para Codex CLI autenticado com ChatGPT Business no VPS.
- Codex le a copia temporaria do repositorio, trabalha em modo de leitura, devolve o relatorio em comentario na Issue.
- O workflow nao publica aplicacoes nem faz alteracoes no VPS de producao.
- Teste end-to-end: [Issue 49](https://github.com/martaxi-boss/VPS/issues/49).

## Comandos em linguagem natural
O utilizador pode dar qualquer instrucao pelo ChatGPT. O ChatGPT interpreta a ordem, escolhe o repositorio e cria a tarefa formal com o titulo de comando compatível. A sequencia dos agentes e as alternativas de quota dependem exclusivamente de cada pedido, nao de percentagens fixas.

Exemplos:
- "Codex, audita a seguranca dos scripts VPS e relata os riscos."
- "Composer, implementa X; depois Sonnet audita e corrige."
- "Codex, revê Y. Se estiver sem quota, passa ao Composer."
As duas ultimas ordens continuam exemplos de fornecedores ainda desligados: nao executam Composer/Sonnet. As ordens Codex suportadas continuam reais atraves de `[codex run]` e do encaminhador Codex validado.

## Regra de ativacao por ordem do Owner

- Por defeito, uma ordem ChatGPT **"trabalha comigo e um Codex"** produz **uma** tarefa e usa apenas **um Codex**. O ChatGPT interpreta a linguagem natural e prepara o manifesto JSON; o workflow GitHub nao infere agentes a partir de texto livre.
- Duas instancias so se ativam quando o Owner pede **dois** agentes, declarando `tasks` com dois IDs e `mode: serial` ou `mode: parallel`. Nao ha segundo trabalhador automatico por existir capacidade para dois.
- A escolha automatica de modelo ou do saldo de quota **nao esta ligada**. A conta Codex disponibilizada permanece `gpt-5.6-sol` Medium neste executor, com contagem observada por tarefa mas percentagem de quota desconhecida.
- Nao interpretar uma recomendacao inteligente do ChatGPT como permissao implicita para duplicar consumo. Sem ordem explicita para dois, manter uma instancia.

## Nucleo generico do planeador
`ops/agent_switch.py` aceita um manifesto JSON com `target_repository`, `mode`
(`serial` ou `parallel`) e uma lista ordenada `tasks`. Cada tarefa tem `id`,
`provider` e `task`; `model` e `reasoning_effort` sao opcionais e limitados aos
valores comprovados pelo adaptador. IDs como `codex-1` e `codex-2` identificam
instancias distintas sem tornar o contrato exclusivo de Codex. A forma legada
`tasks: {"codex": "..."}` continua valida para pedidos de um Codex.

O planeador produz um plano versionado, com identidade, fornecedor, modo,
dependencias derivadas e politica que proibe substituicao implicita.
O encaminhador GitHub suporta o caminho legado de **um Codex** sem criar
outros agentes, e tem agora um backend delimitado para **dois Codex** quando
a ordem do Owner pede explicitamente `serial` ou `parallel`.
Em modo serial, a segunda execucao so inicia se a primeira acabar com
sucesso; uma PR nao integrada interrompe a sequencia. Em paralelo, os dois
trabalhadores usam workspaces/branches distintos e publicam **PRs separadas
sem auto-merge**, para evitar fusoes concorrentes. O acesso Codex partilhado
fica limitado por dois slots de execucao partilhados com os caminhos de
auditoria e proposta Codex; continua a partilhar a quota da mesma conta.

O planeador generico suporta planos de ate oito tarefas, mas o backend real
esta deliberadamente limitado a um ou dois Codex. Mais de dois, ou qualquer
fornecedor desligado, falha antes de executar modelos — nunca corre so metade
da ordem. A execucao de **duas tarefas de leitura sem patch** foi comprovada ao vivo:
[paralelo #102](https://github.com/martaxi-boss/VPS/issues/102)
(run 38081330336) e
[serie #103](https://github.com/martaxi-boss/VPS/issues/103)
(run 38081707953); ambos os modos tiveram dois executores concluidos com
Skill Project Leader v0.7.0 pinada. Isto NAO certifica duas alteracoes reais
de codigo nem o merge/reconciliacao de PRs concorrentes.
A selecao de modelos alternativos e otimizacao dinamica de quota permanecem
por integrar: o executor validado continua em `gpt-5.6-sol` Medium.

O registo de adaptadores deixa Codex disponivel. Gemini, Composer e Claude estao
registados mas indisponiveis ate existir um adaptador autenticado, testado e
autorizado. Nao ha fallback nem troca de fornecedor sem ordem expressa. O estado
do planeador nao constitui evidencia de quotas ou disponibilidade semanal.

## Preparacao para o Cursor (ligacao pendente)
Implementar Cloud Agents da conta Cursor quando a conta ficar ativa. O contrato de cada etapa e:
- `provider`: `codex` | `cursor`
- `agent`: `codex` | `composer` | `sonnet`
- `mode`: `audit` | `fix` | `build` | `test`
- `repository`, `branch`, `task`, `depends_on`.
- `on_unavailable`: passo alternativo definido pelo utilizador na ordem.
- `result`: estado `success` | `failed` | `quota_blocked` | `waiting`, links para Issue/PR, relatorio.

Cada etapa deve deixar o codigo numa branch e devolver metadados para a proxima. Nao assumir limites de quota em tempo real. Quando um agente falhar, guardar o progresso e usar somente o alternativo autorizado no pedido. Sem alternativa, aguardar instrucao.

## Avisos
- Imediato: GitHub pode notificar os participantes dos comentarios em Issues, desde que as notificacoes do utilizador estejam ativadas.
- ChatGPT: existe uma tarefa de monitorizacao horaria de resultados de Issues Codex (nao e push instantaneo e depende da disponibilidade do conector GitHub nessa tarefa). Ativar notificacoes do ChatGPT no telemovel.
- Os resultados continuam acessiveis no GitHub sem abrir terminal VPS.

## Protecoes
- No repositorio VPS publico, prompts, comments e PRs tambem podem ser publicos. Nao enviar dados privados ou segredos.
- Nunca colocar token do Codex ChatGPT Business nos GitHub Secrets para esta integracao: Codex ja tem login por codigo de dispositivo no VPS.
- `[codex audit]` continua read-only. `[codex run]` executa alteracoes num clone isolado, cria PR automaticamente e so faz merge no VPS documental se os controlos passarem; a `main` do Project Leader permanece sujeita ao gate E2. Nao assumir que Cursor, Gemini, Sonnet ou Telegram fazem correcoes automaticas: essa fase ainda nao esta comprovada.
- Gemini/Antigravity, Cursor/Composer e Claude ainda nao tem adaptadores ligados.
- As duas provas reais com Codex foram tarefas sem alteracoes; o pipeline multiagente ainda nao foi certificado para reconciliar multiplas PRs com codigo modificado.
- O manifesto `[agents run]` pode declarar `"allow_no_change": true` **apenas para tarefas de leitura sem alteracoes esperadas**, individualmente por agente. Sem essa permissao, um patch vazio produz `NO_CHANGE_UNVERIFIED`, falha o workflow e bloqueia a etapa seguinte da serie em vez de alegar cumprimento do objetivo. Com permissao, `NO_CHANGE` certifica apenas ausencia de diff, nao a qualidade da resposta.
- O GitHub Actions usa fila `queue: max` para nao substituir ordens pendentes normais (limite da plataforma: ate 100 pendentes por grupo). Se a etapa 1 falhar, o Owner recebe uma anotacao `CODEX_2_NOT_STARTED`.
- Os workspaces de executor passam a ter remocao tentada tambem quando houve falha, apos recolher o resultado. A tentativa pode falhar se a VPS estiver inacessivel; nao se afirma limpeza perfeita.
- O relatorio textual detalhado do Codex em `[agents run]` e `[codex run]` e recolhido num runner temporario e enviado **apenas ao chat privado Telegram do Owner ja configurado** com `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID`, sem texto do modelo nas Issues publicas. Se nao existirem estes segredos, se a entrega falhar ou se o relatorio exceder o limite, a Issue indica `NOT_CONFIGURED`, `NOT_DELIVERED`, `OVERSIZED_REPORT_NOT_SENT` ou `NOT_OBSERVED`, sem alegar entrega. Esta nova via so tem validacao de codigo ate haver teste real com Telegram; nao implica publicacao automatica no ChatGPT.
- O repositorio e publico: qualquer futuro retorno de relatorios tem de preservar privacidade e impedir divulgacao de segredos, nao publicar texto arbitrario do modelo por defeito.
