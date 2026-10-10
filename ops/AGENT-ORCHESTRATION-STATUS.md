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
As duas ultimas ordens sao planos para fases futuras: ainda **nao executam** Composer/Sonnet nem correcoes Codex neste workflow.

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
- A ligacao Cursor e a orquestracao multiagente ainda nao estao ativas.


## Nomes e cadeia de execução por voz no Telegram (proposta)

- Endereçamento: «Oh Codex», «Boa tarde Composer» e «Olá Sonnet» identificam agentes distintos, sem criar tarefas pagas. O comando /agentes apresenta o estado conhecido.
- «Oh Codex, executa o projeto e quando acabares os tokens passa para o Composer acabar» é reconhecido como uma cadeia de implementação, não como uma auditoria. Enquanto o Composer não estiver ligado, a cadeia é recusada antes de consumir tokens Codex.
- Para executar a passagem real é preciso ligar os dois executores com autenticação e âmbitos próprios, um sinal verificável de quota/rate-limit sem inventar percentagem, um ponto de continuação privado com repositório, branch e SHA, testes de não duplicação e autorização de alteração/publicação.
- O Telegram ainda não oferece conversa livre equivalente ao ChatGPT; esta mudança prepara identificação e segurança, mas não liga por si só um modelo de chat ou o Composer.
- A preparação está numa PR não integrada; o serviço residente também não está confirmado como instalado na VPS.


## Diferença entre o Project Leader e a entrada Telegram

**Project Leader 0.7.0 não está limitado a auditoria.** As capacidades canónicas incluem Consultant, Supervisor, Builder (execução), Recovery Guardian e higienização, sob limites e autorização proporcional. O workflow GitHub de implementação Owner-autorizada `[codex run]` carrega a Skill canónica antes de invocar o Codex, executa num clone descartável com sandbox workspace-write e submete alterações a controles/CI/publicação independentes. Não equivale a uma invocação direta do plugin no ChatGPT e não autoriza produção sem gates aplicáveis.

O bot **Telegram** existente encaminha `[codex audit]`, não `[codex run]`. Esta fronteira é da autenticação e da entrada de mensagens (que ainda não satisfaz a validação Owner para tarefas de escrita), não uma falta de execução na Skill. A migração correta tem de ligar Telegram autenticado ao circuito já existente sem contornar a verificação do proprietário, scoped token, privacidade, ponto de continuação e limites de confiança. Não declarar o bot capaz de executar ou passar ao Composer sem uma prova real ponta-a-ponta.
