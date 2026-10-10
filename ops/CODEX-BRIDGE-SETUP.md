# Codex CLI: ChatGPT -> GitHub Issues -> GitHub Actions -> VPS

## Estado da integracao

O Codex CLI v0.162.1 ja foi instalado no VPS Ubuntu em
`/home/ubuntu/codex-agent/node_modules/.bin/codex` e autenticado pelo
proprietario atraves de `codex login --device-auth`.

A autenticacao fica no perfil do utilizador `ubuntu` no VPS.
**Nao criar nem copiar um token ChatGPT para o GitHub Actions.**

Este fluxo usa o segredo SSH `VPS_SSH_PASSWORD` que o repositorio ja utiliza
noutras automacoes para ligar ao VPS. Nao guarda a senha nem a credencial Codex
no codigo-fonte, nos artefactos ou nas mensagens.

## Como enviar tarefas pelo ChatGPT

Criar uma nova Issue no repositorio `martaxi-boss/VPS` com titulo comecado
exatamente por `[codex audit]` (letras minusculas) e colocar as instrucoes
em linguagem natural no corpo da Issue. Exemplo:

> Titulo: [codex audit] Verificar seguranca e regressao dos scripts VPS
>
> Corpo: Analisa estaticamente o repositorio VPS, identifica riscos e testes
> que faltam. Nao executes scripts, nao modifiques ficheiros nem facas deploy.

So Issues **abertas pelo proprietario do repositorio** desencadeiam uma tarefa.
Tambem e possivel iniciar manualmente em Actions / Codex - ChatGPT bridge,
atraves de `Run workflow`, com uma instrucao propria.

O GitHub Actions:
1. Guarda o prompt como um ficheiro de dados (nao comando shell).
2. Usa SSH para criar uma pasta temporaria privada em
   `/home/ubuntu/codex-bridge/jobs/<run>-<attempt>`.
3. Transfere o runner confiado do repositorio e o ficheiro do prompt.
4. No VPS, verifica `codex login status`, clona uma copia nova do repositorio
   GitHub e executa `codex exec --sandbox read-only`.
5. Obtem o relatorio e publica-o como comentario na Issue e artefacto Actions.
6. Elimina a pasta temporaria apos sucesso. Falhas deixam a pasta para diagnostico.

## Auditoria pontual ao Project Leader

O Codex continua limitado a auditorias de leitura. Para auditar as regras
canonicas do Project Leader, com uma Issue de auditoria criada pelo Owner,
colocar **na primeira linha do corpo**:

`TARGET_REPOSITORY=martaxi-boss/Project-leader`

O texto seguinte descreve a auditoria desejada. O runner aceita apenas
`martaxi-boss/Project-leader` ou `martaxi-boss/VPS` como alvos explicitos,
rejeita alvos desconhecidos, clona o `main` publico numa pasta descartavel,
e regista o SHA efetivamente auditado. Sem esta linha, mantem a auditoria
do VPS. Nenhuma permissao de escrita, deploy ou acesso a producao e adicionada.

## Regras canónicas do Project Leader nas auditorias

Cada tarefa `[codex audit]`, incluindo a entrada de auditoria do Telegram,
carrega primeiro a mesma Skill canónica do Project Leader usada por `[codex run]`,
fixada a um SHA exato de `martaxi-boss/Project-leader/main` e validada
contra o manifesto e a autoridade. O SHA e a versão entram no relatório.
Falha de carregamento impede o Codex de arrancar; a auditoria mantém-se
estritamente **read-only**, sem escrever código nem limpar a VPS.

## Modelo Standard para as auditorias Codex

O runner `ops/codex-vps-remote.sh` fixa o modelo `gpt-5.6-terra` com
raciocinio `medium` em cada execucao automatica (GitHub ou Telegram).
A opcao `--model` so se aplica a este bridge; nao altera o seletor do ChatGPT,
as definicoes globais do Codex nem os modelos do Cursor.
O workflow mostra `CODEX_MODEL` e `CODEX_REASONING_EFFORT` nos logs.
Se a conta/CLI nao aceitar este modelo, a auditoria falha explicitamente;
nao ha fallback silencioso para um modelo mais caro. A disponibilidade real
deve ser confirmada com uma primeira execucao autorizada.
Para mudar a configuracao, editar `codex_model` e `model_reasoning_effort`
no mesmo script, numa branch e com revisao/testes.

## Limites / precaucoes

- **Apenas auditoria estaticamente e sem alteracoes nesta primeira fase.**
  Pedidos `[codex fix]` nao ativam este workflow.
- **O VPS de producao e a conta Ubuntu sao partilhados com outros servicos.**
  O Codex trabalha numa copia separada de codigo e usa sandbox read-only,
  mas esta configuracao NAO substitui um ambiente SO isolado/dedicado.
  Nao colocar instrucoes nao confiaveis no prompt nem dar permissao para
  corrigir/instalar/deploy antes de preparar um executor isolado.
- O repositorio VPS e publico: **Issues, comentarios e resultados podem ser
  publicamente visiveis**. Nunca incluir credenciais, dados privados ou segredos.
- O GitHub Actions nao copia os ficheiros de autenticacao do Codex; o CLI
  usa o login ChatGPT Business ja configurado no VPS.
- Os limites de quotas Codex continuam a aplicar-se. Falhas ficam registadas;
  nao ha passagem automatica para Cursor sem a integracao especifica.
- Dependencia SSH usa `StrictHostKeyChecking=accept-new` como workflows
  existentes. Endurecer com host key SSH previamente validada numa fase futura.
- Nenhuma tarefa deste fluxo faz deploy, edita codigo ou gera PR com correcoes.
- Se a autenticacao ChatGPT expirar no VPS, executar de novo
  `"$HOME/codex-agent/node_modules/.bin/codex" login --device-auth`
  na sessao segura do utilizador ubuntu.

## Como validar

1. Confirmar que a autenticao Codex aparece como
   `Logged in using ChatGPT` no terminal VPS.
2. Abrir Issue do proprietario com titulo
   `[codex audit] Teste de ligacao` e corpo nao sensivel.
3. Confirmar a execucao em Actions e o comentario final da Issue.

A integracao Cursor e a gestao dinamica de quotas ficam para fases seguintes.

## Notificacoes automaticas

O GitHub Actions devolve os resultados a Issue criada pelo ChatGPT. O ChatGPT
agora tem uma tarefa de monitorizacao horaria dos resultados, que pode enviar
uma notificacao no telemovel se estiverem ativas as notificacoes das tarefas.
Para avisos mais rapidos, ativar notificacoes do GitHub Mobile para Issues em
que o utilizador participa. Isto nao altera o metodo de autenticar o Codex.

## Preparacao para outros agentes

Ver `ops/AGENT-ORCHESTRATION-STATUS.md` para o contrato de tarefas de Cursor
Composer/Sonnet. Este documento nao implica que o Cursor esteja ligado.
