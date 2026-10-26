# REA P311 - SIMPLES: so ferramentas sensiveis (26/10/2026)

## Objetivo do proprietario
1. O utilizador descreve uma tarefa e o REA seleciona as ferramentas.
2. Ferramentas normais mantem a politica anterior, sem um novo botao GitHub.
3. Quando a tarefa contem ferramentas SENSIVEIS, o GitHub apresenta apenas
   APROVAR / RECUSAR na environment protegida `rea-p311-owner-consent`.
4. A aprovacao autentica do proprietario no GitHub tem de coincidir com UMA
   tarefa concreta, de prazo limitado e JA assinada por Ed25519 pelo dono.
   Assinar uma tarefa nao e assinar cada ferramenta; o clique nunca substitui
   a assinatura Ed25519 nem permite uma autorizacao universal.
5. O REA reutiliza a autorizacao delimitada para as ferramentas sensiveis
   incluidas nela, sempre aplicando efeitos auditados, schema, paths,
   expiracao, revogacao, nonce e replay fail-closed.

## Implementacao minima
- Motor REA 6.8.0 original intacto; a MESMA ponte GitHub Actions / SSH / MCP.
- GitHub owner approval por environment, identificadores de conta e repositorio
  fixos, GitHub REST autenticado, run completed/success e commit/blob imutavel.
- O DESAFIO publico contem apenas o digest do grant ja assinado; o grant completo
  viaja cifrado na ponte existente. Nao ha novo servidor, plugin, MCP, JWT/OIDC
  nem segundo botao/servico de identidade.
- O GitHub runner ja autenticado fornece apenas credencial REST temporaria
  dentro da sessao SSH cifrada, nunca no pedido publico.
- So grants com ferramentas classificadas `sensitive` podem ser registados
  neste percurso. As ferramentas normais nao foram migradas para o gate.
- A ativacao do P311 e opt-in por invocacao `sealed_task_enroll` ou
  `sealed_batch` na ponte e nao altera a configuracao permanente do daemon.
- Ficheiros e diretorios privados 0600/0700; registo unico O_EXCL.
- NUNCA apagar Evidence, Unknowns, backups ou certificados.

## Proveniencia e condicoes de fecho
- PR #305 no ramo experimental `rea/p311-autonomia-escopos-20261026`,
  base operacional preservada em `2f5573be27302f22aca5b9b3e20d78244f3ad0dc`.
- Historico de engenharia da versao complexa/OIDC retido nos commits Git;
  nao faz parte do percurso operacional atual.
- Testes offline nao provam aprovacao real nem execucao MCP.
- Para teste REAL sensivel: tarefa concreta, grant com assinatura Ed25519
  do proprietario no Android, novo clique GitHub, leitura privada na VPS,
  tool-call autorizado e prova de revogacao/rollback. A aprovacao historica
  P311 nao pode ser reutilizada.
- NAO fazer merge, restart, alterar politica permanente ou abrir ferramenta
  sensivel sem provas reais e autorizacao autentica.
