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
- Modelo autenticado gpt-5.6-sol; a escolha de raciocinio Low/Medium/High por tarefa esta ligada e comprovada na Issue #111. Percentagem da quota semanal da conta permanece desconhecida; o limite local de tokens e soft e nao pode garantir interromper uma chamada a meio.
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
Nao ha troca de modelo nem fornecedor: o executor validado continua em gpt-5.6-sol,
com esforco adaptativo por tarefa. A quota semanal real nao e exposta. A VPS
nao aplica um teto proprio de tokens nem infere disponibilidade da conta a
partir do contador local; as recusas de quota sao decididas pelo fornecedor
ChatGPT autenticado.

O registo de adaptadores deixa Codex disponivel. Gemini, Composer e Claude estao
registados mas indisponiveis ate existir um adaptador autenticado, testado e
autorizado. Nao ha fallback nem troca de fornecedor sem ordem expressa. O estado
do planeador nao constitui evidencia de quotas ou disponibilidade semanal.

## Politica semi-automatica Codex operacional (PR #108 e prova real #111)

- Os **dois Codex** continuam a ser **duas execucoes isoladas da mesma conta** na VPS. O limite de duas chamadas simultaneas usa os bloqueios ja existentes; nenhuma segunda conta ou nova chave de Codex e criada.
- O plano do Owner seleciona **uma ou duas tarefas** com `mode: serial` ou `mode: parallel`; so executa duas se o manifesto tiver dois IDs distintos. A versao atual nao cria um segundo trabalhador por adivinhacao.
- Em cada tarefa o Project Leader pode enviar `reasoning_effort: "auto"` (ou omitir o campo): tarefas simples e delimitadas usam `low`, tarefas normais `medium`, problemas com indicios objetivos de elevada complexidade `high`. `low`, `medium` e `high` tambem podem ser fixados manualmente. O modelo autenticado continua a ser `gpt-5.6-sol`; nao ha troca automatica de fornecedor nem promessa de nivel Pro.
- A escolha e **por tarefa/turno Codex**, nao uma mudanca invisivel a meio do mesmo pedido. Na etapa seguinte, o Project Leader pode subir ou descer o nivel mediante CI/falha, contexto e objetivo. Nunca aumenta o nivel para repetir cegamente uma falha.
- O executor regista cada tarefa num ledger privado, sob bloqueio atomico e com protecao contra repeticao. As estimativas contabilisticas sao Low=12k, Medium=35k e High=75k quando nao ha dados reais; ao terminar usa tokens observados em JSONL. Input em cache faz parte do input e nao e contado duas vezes. Estas estimativas **nao sao uma autorizacao ou um teto de quota**.
- O ledger e privado na VPS e nao guarda prompt, identidade da conta, chave ou credencial. Abrange os executores `[codex run]`/`[agents run]`; outros consumidores da conta podem gastar utilizacao sem aparecer neste registo. O antigo teto artificial de 300 mil tokens/24h foi retirado por ordem expressa do Owner.
- Antes de usar o modelo, a CLI tem de confirmar login ChatGPT; os dois executores fixam o fornecedor nativo `openai`, fixam a URL efetiva do fornecedor em `https://chatgpt.com/backend-api/codex`
e a base de autenticacao ChatGPT oficial, em vez de uma URL vazia ou customizada. Modo API key ou variaveis de faturacao API sao recusados. O limite real fica a cargo da conta ChatGPT, e a percentagem semanal continua **UNKNOWN** na CLI. Mantem-se os dois slots, o timeout e o isolamento.
- Este caminho permanece submetido a revisao de patches, PR/CI, protecao de codigo e sem auto-merge de trabalhos paralelos. Gemini, Cursor, Composer e Sonnet continuam desligados. A prova de comportamento real com Low/High sera registada separadamente; testes locais/CI nao sao apresentados como consumo real Codex.


## PINK IPTV como terceiro repositorio alvo (integracao PR-only)

O Owner autorizou explicitamente dois Codex para reforcar a PINK IPTV. Alem dos
repositorios martaxi-boss/VPS e martaxi-boss/Project-leader, o adaptador
permite apontar tarefas independentes para martaxi-boss/pink-iptv em clone
privado/temporario com a Skill Project Leader canonicamente pinada.

**Seguranca fail-closed:** o modelo nao possui credenciais GitHub de escrita.
O runner valida que CODEX_GITHUB_TOKEN ja possui Contents write no exato
repositorio PINK antes de gastar tokens. O token atual pode estar limitado
a VPS e Project-leader; nao presumir que foi alargado. Nunca pedir ao Owner
que cole tokens no chat, Telegram ou issues publicas.
Se nao houver esta permissao, registar NOT_STARTED ate o consentimento
apropriado ser concedido, sem fallback para uma conta nao autorizada.

**Publicacao:** PR isolada por trabalhador, sem merge automatizado na PINK
IPTV, incluindo simples README. Como a CI Android/backend da PINK tem triggers
por paths e nao existe um perfil universal obrigatorio, nenhuma PR pode alegar
CI completa a partir da ausencia de runs: PR_NEEDS_ATTENTION requer auditoria,
testes apropriados e integracao independente do Project Leader. Sem acesso
a producao, segredos de clientes ou deploy.

**Prova:** Issue #111 https://github.com/martaxi-boss/VPS/issues/111
(run 38086086361) terminou com dois Codex reais no mesmo login, slots 1 e 2,
um Low (34 803 input, 23 936 cached, 343 output), outro High
(312 280 input, 282 624 cached, 4 998 output). Ambos devolveram
NO_CHANGE autorizado e relatorios privados ao Telegram; isto nao comprova
qualidade funcional nem modificacoes no repositorio PINK. O High ultrapassou
a estimativa inicial de 75k, mostrando por que a contabilizacao local nao
deve substituir a quota contratual real. O ledger atual continua a registar
esses valores, mas nao impede novos trabalhos pela soma acumulada.

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
