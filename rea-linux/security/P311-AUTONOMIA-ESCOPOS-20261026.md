# P311 - REA 6.8.0: autonomia por trabalho (preparacao isolada)

**ESTADO: FASE 1 IMPLEMENTADA NUM RAMO DE REVISAO. NAO ATIVADA NA VPS.**

Base imutavel: rea/one-skill-bridge-20261023 @ 2f5573be27302f22aca5b9b3e20d78244f3ad0dc.
Ramo de preparacao: rea/p311-autonomia-escopos-20261026.

## Objetivo
O proprietario define o trabalho, nao a lista de ferramentas MCP. A ponte decide e verifica cada operacao, dentro de permissoes pre-aprovadas; so pede uma confirmacao para operacoes fora das permissoes.

## Estado real
- REA 6.8.0 e MCP na VPS continuam sem alteracoes.
- A ponte ativa: 6 read, 176 workspace com autorizacao especifica, 47 sensitive com assinatura Ed25519 individual.
- A VPS tem a chave PUBLICA, nao a privada do proprietario, que permanece no Android.
- Um botao de demonstracao ou um simples texto "Autorizo" no chat nao provam a identidade perante a VPS.

## Fases
1. **Concluida - laboratorio e GitHub, sem deploy:** modulo ops/rea_scoped_approval_20261026.py e testes ops/tests/test_rea_scoped_approval_20261026.py. O modulo valida uma delegacao por tarefa assinada com Ed25519, com ferramenta/efeitos/projeto/origem/prazo limitados. O codigo NAO e chamado pela ponte ativa. Foram executados oito testes offline locais, todos com sucesso; falta CI remoto.
2. **Pendente - integracao controlada:** validar o contrato MCP real, verificacao SHA dos schemas e efeitos, origem, tarefa, raiz de artefactos e politica P232. Permitir automacao apenas das operacoes pre-aprovadas de baixo impacto, sem qualquer chave privada na VPS. As sensiveis com efeitos destrutivos permanecem com assinatura de proprietario por operacao.
3. **Pendente - confirmacao simples autenticada:** so ligar botoes Autorizar/Recusar quando houver canal de identidade do proprietario verificavel no servidor. Nunca aceitar apenas texto de um prompt, screenshot ou clique ilustrativo como assinatura.
4. **Pendente - ativacao:** depois de validacao positiva e negativa, prova real MCP, seguranca de Evidence/Unknowns, revisao humana da alteracao de politica, e rollback comprovado.

## Proposta limitada nesta fase
- Grant Ed25519 uma vez, reutilizavel no MESMO projeto e tarefa, com expiracao maxima de sete dias.
- Sem alteracao do codigo do autor.
- Proibidas delegacoes de mutatesTarget, mayDiscardData, changesUiState, executesForeignCode, mutatesDevice e accessesNetwork.
- Proibidas delegacoes para close_binary, alteracoes de Evidence/Unknowns e comandos poderosos do debugger.
- A verificacao de assinaturas nunca e substituida por um booleano no JSON.
- No transporte definitivo manter RSA-OAEP/AES-GCM, SSH com host pin, MCP loopback, nonce de uso unico, limite de 12 passos e isolamento dos ficheiros.

**NAO DECLARAR:** nem que as 47 operacoes ja sao automaticas, nem que o modulo isolado fornece aprovacao real por botoes, nem que oito testes offline sao prova de funcionamento na VPS.

## Evidencia verificada desta continuacao (P311, 26/10/2026)

- **40/40 testes offline:** Actions run 40373089872 PASS, contendo os testes
  existentes de seguranca e verificacoes de delegacao, assinaturas falsas,
  esquema alterado, efeitos proibidos, caminhos e origem de projeto.
- **Integracao de envelope cifrado em revisao:** protocolo original 1 com campo
  opcional `scoped_task`. Quando ausente, o comportamento anterior e mantido.
  Quando presente mas a funcionalidade nao esta ativada, o pedido e recusado.
  O valor nunca e tratado como aprovacao por si so: exige Ed25519 autentico.
- **Selecao automatica de ferramentas:** funcao `propose_task_tools` prepara
  uma lista de ferramentas elegiveis a partir do catalogo real e auditoria
  fonte/schema; o proprietario nao precisa de nomear ferramentas. A proposta
  NAO executa ferramentas nem cria uma autorizacao.
- **Teste MCP real de transporte somente de leitura:** run 40372781885 PASS;
  `REA_MOBILE_JOB_FILE=default-catalog`, SSH host pin PASS, MCP loopback PASS,
  229 ferramentas, 176 workspace, 47 sensiveis, 229 schemas validados.
  NENHUMA operacao MCP `tools/call` foi enviada nesse teste.
- **Higienizacao:** disparador temporario do ramo P311 retirado do workflow;
  nao existem ficheiros de pedidos nas pastas `rea-linux/requests` e
  `rea-android/requests` verificadas. O ramo ativo conserva o HEAD
  `2f5573be27302f22aca5b9b3e20d78244f3ad0dc`. Nenhum service restart,
  manutencao de Evidence, Unknowns e certificacoes historicas intacta.

## Distincao entre demonstracao e autorizacao operativa

Esta fase ainda nao aplica autorizacoes automaticas na VPS: nao ha grant
real do proprietario para este prototipo, a flag opt-in nao esta ativa, e
nao existe backend para validar um botao do chat como identidade do owner.
As operacoes normais podem continuar a usar o contrato anterior. As 47
sensiveis mantem as assinaturas independentes quando nao houver um grant
validado e autorizado pela politica de producao.

O grant experimental dura **no maximo 7 dias** por desenho e NAO e ainda
uma permissao permanente. Para o uso autonomo duradouro pretendido pelo
proprietario sera necessario um contrato de politica revogavel, confirmado
por um canal que ateste o owner, sem expor a chave privada. Nao substituir
esse requisito por um checkbox, booleano, mensagem ou ficheiro publico.

## P311 reforco de seguranca e prova MCP real (26/10/2026)

- **46/46 testes offline PASS**, incluindo round-trip da propria carga
  `scoped_task` atraves de RSA-OAEP e AES-GCM, verificacao da assinatura
  Ed25519 e rejeicao de adulteracao no ciphertext. Actions:
  https://github.com/martaxi-boss/VPS/actions/runs/40374688244
- Delegacoes de tarefa deixam de aceitar caminhos escondidos em argumentos
  de texto/listas, aliases como `source_file`, chaves de execucao ou URI;
  o acesso aos artefactos tem de permanecer no diretorio assinado.
- Revogacao: `revoked-p311-grants/<grant_id>.revoked` no diretorio de
  politica privada da conta SSH. O verificador apenas LE, recusa marcador
  presente e tambem diretorios ou marcadores com ownership, modo ou
  symlinks inseguros. Nao cria/remover marcadores automaticamente.
- **Chamada MCP real de leitura PASS:**
  https://github.com/martaxi-boss/VPS/actions/runs/40375171071
  `REA_MOBILE_JOB_FILE=rea-linux/requests/p311-readonly-list-20261026.json`
  `REA_MOBILE_REQUEST_ACTION=call`; SSH host pin PASS; MCP loopback PASS;
  `REA_MOBILE_MCP_TOOL_COUNT=229`;
  `REA_MOBILE_TOOL_CALL=PASS`; `REA_MOBILE_TOOL_NAME=list_unknowns`;
  `REA_MOBILE_TOOL_ERROR=false`. Resposta privada nao foi impressa.
- **Higienizacao comprovada:** o pedido de uso unico e o gatilho temporario
  do ramo de testes foram eliminados no commit
  `a24fa6b1846dd48585eb04c3b54262bdb9ece4c3`, com arvore final
  `ddf61bd641f7b3e9b2fce25dcc0a406a1fa258bf`, identica a arvore
  anterior ao ensaio. Ramo ativo sem mudancas.

### Limitacoes deliberadas

A chamada `list_unknowns` valida o **transporte e uma ferramenta read real**;
nao valida uma ferramenta sensivel por delegacao. Os 46 testes de
`scoped_task` continuam offline. O canal autentico de aprovacao por
botao, autorizacao de owner real, ativacao da politica na VPS e teste
real sensivel permanecem pendentes. O REA original nao foi modificado.

## P311 final - fail-closed de revogacao

- O diretorio privado `revoked-p311-grants` passou a ser **obrigatorio**
  para qualquer tarefa autorizada com grant persistente. Se nao existir,
  for symlink, nao pertencer ao utilizador SSH ou nao tiver modo 0700,
  a autorizacao e recusada. Marcadores de revogacao com modo 0600 e
  propriedade correta impedem o reuso do grant. O verificador nao cria
  nem remove marcadores.
- A preparacao inicial desse diretorio fara parte do futuro **registo
  autenticado do proprietario**, nunca de um pedido publico GitHub.
- Regression run PASS (46/46) apos esta correcao:
  https://github.com/martaxi-boss/VPS/actions/runs/40375847498
- Chamada MCP read real e higienizacao do pedido/trigger continuam provadas
  pelos commits e run anteriores. Nao houve qualquer ativacao na VPS.

## P311 - prova de assinatura unica com chave existente (26/10/2026)

**61/61 testes PASS** (sem VPS/SSH/segredos em producao): https://github.com/martaxi-boss/VPS/actions/runs/40377570368

- Foi preparado o helper offline `rea-linux/owner/p311_sign_task_grant.py`, que usa a MESMA chave Ed25519 do proprietario no dispositivo Android, sem gerar ou exportar uma nova chave.
- O utilizador ve um resumo de projeto, tarefa, raiz, ferramentas e validade e pode responder `sim` ou `nao`. Apenas `sim` gera a assinatura e o ficheiro JSON privado, com permissoes `0600` e escrita exclusiva.
- Foi preparada a funcao `prepare_unsigned_task_grant` que seleciona ferramentas a partir da proposta interna do planificador REA, do catalogo MCP e das politicas de efeitos e schema SHA-pinned. O proprietario nao precisa de indicar nomes das ferramentas.
- Os testes cobrem `sim`/`nao`, assinaturas existentes e falsas, chave com modo inseguro, root fora do projeto, expiracao, efeitos proibidos, ferramentas inseguras, selecao de ferramentas e revogacao.
- Um teste usa a assinatura do helper no validador experimental MCP para uma ferramenta de classe sensivel e confirma a recusa apos revogacao. Nao se trata de execucao real sensivel na VPS.

**Nao concluido:** a autorizacao pelo botao autenticado do ChatGPT/GitHub ainda nao foi implementada. O `sim` do helper e dado no dispositivo do proprietario, nao no chat. A delegacao experimental dura no maximo sete dias, nao e uma permissao permanente. A flag de producao continua DESLIGADA e nao foi registado um grant do proprietario real.

Higienizacao: nenhum pedido temporario novo publicado, nenhuma chave privada copiada, nenhum motor original alterado, nenhum deploy ou service restart. PR #305 continua DRAFT, ramo ativo em `2f5573be27302f22aca5b9b3e20d78244f3ad0dc`.
