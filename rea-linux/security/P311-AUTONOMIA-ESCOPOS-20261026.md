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

## P311 continuacao: autorizacao por referencia privada, 96 testes (26/10/2026)

- **96/96 PASS** no CI exclusivamente offline: https://github.com/martaxi-boss/VPS/actions/runs/40380482852
- `propose_p311_task_from_live_catalog`: aceita apenas o conjunto completo 208/229 de ferramentas MCP source-attested e schemas SHA-pinned. Contratos desconhecidos, ausentes, alterados ou manipulados nao produzem propostas de concessao.
- `validate_inner` recusa um `scoped_task` presente mas nunca usado/verificado. Misturar validamente uma aprovacao tradicional com uma concessao assinada na mesma tarefa continua possivel.
- Registro experimental: o proprietario assina UMA vez, o codigo de VPS valida todos os efeitos de ferramenta contra o catalogo original e grava apenas o grant assinado em `approved-p311-tasks/<32hex>.json` no diretorio privado, modo `0700/0600`, criacao exclusiva sem overwrite.
- Em pedidos cifrados posteriores, `scoped_task_id` referencia essa concessao; cada pedido revalida Ed25519, projeto, tarefa, root, efeitos auditados, validade e registo de revogacao. Um ID sozinho nunca e comprovativo de autorizacao.
- Os testes 208 e simulacoes do contrato 229 incluem reutilizacao multi-pedido, revogacao, symlinks, permissao insegura, adulteracao, falta de registo, grants expirados e ausencia da flag opt-in.
- Nenhum grant real foi registado na VPS; nenhum comando MCP sensivel real foi executado durante estes testes. A producao continua na politica antiga.

### Proxima porta de autenticacao simples

GitHub Actions suporta `Environments` com `Required reviewers` e botoes `Review deployments` / `Approve and deploy` no GitHub autenticado. Este repositorio e publico, portanto o recurso e elegivel segundo a documentacao oficial: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments e https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/review-deployments

Mas um botao ilustrativo no ChatGPT nao fornece uma assinatura criptografica para a VPS. Uma `environment` sem revisores configurados no GitHub nao e um gate! Nao acrescentar `environment:` ao workflow de producao ate haver revisores explicitamente configurados, impedimento de bypass e uma verificacao no servidor que ligue a aprovacao ao hash do pedido concreto e ao projeto.

A integracao de botoes continua nao concluida. A assinatura unica com a chave privada do Android e o unico procedimento Ed25519 real disponivel nesta fase. Nem o GitHub nem a VPS receberam a chave privada.

Higienizacao: PR #305 ainda draft sem merge. Nenhum novo ficheiro de pedido consumivel foi introduzido nesta continuacao, a pasta temporaria de teste e exclusiva ao CI, os runs e provas foram preservados. Nao tocar Evidence, Unknowns ou certificados.

## P311: registo cifrado no transporte existente (26/10/2026)

- **106/106 testes offline PASS**: https://github.com/martaxi-boss/VPS/actions/runs/40381893124
- Implementada em ramo de revisao, DESLIGADA: acao `sealed_task_enroll` no mesmo modulo `ops/rea_mobile_mcp_bridge_20261022.py` e workflow GitHub/SSH ja existentes. Nao cria outro MCP, plugin, servidor ou Skill.
- Pedidos de registo contêm apenas `version=1`, `action=sealed_task_enroll`, `sealed` autenticado com RSA-OAEP/AES-GCM e uma chave publica de resposta. Os dados de aprovacao do proprietario circulam DENTRO do envelope cifrado, nunca em texto claro no GitHub.
- A mensagem cifrada obrigatoriamente contem `protocol=1`, nonce de uso unico, validade de pedido ate 1 hora e `signed_task` com assinatura Ed25519 independente do proprietario. O servidor exige `REA_P311_SCOPED_TASKS=enabled`, chave publica original da conta SSH, catalogo MCP completo e manifesto oficial 6.8.0 SHA-pinned.
- Antes de registar, a ponte verifica efeitos e schemas reais da origem, projeto/tarefa, duracao, root de artefactos e revogacao. Reclama o nonce uma vez e grava o grant privado apenas com criacao exclusiva `0600`. Responde com recibo cifrado; sem `tools/call` para este registo.
- Testes de 208 nomes e 229 nomes (229 sinteticos, com compromisso SHA fiel ao formato 6.8.0): assinatura falsa, nonce repetido, expiracao, efeitos proibidos, revogacao, reply cifrado, adulteracao de manifesto, esquema e formato exterior. Chaves de teste sempre efemeras.
- A flag de producao NAO esta ativa, nenhum grant real do proprietario foi emitido ou gravado na VPS e nenhum teste real de ferramenta sensivel aconteceu. A prova real MCP read-only existente permanece https://github.com/martaxi-boss/VPS/actions/runs/40375171071.
- Uma revisao via botao no GitHub ou ChatGPT NAO equivale a Ed25519; a aprovacao por botao autenticada continua PENDENTE. O utilizador nao deve colocar a chave privada no GitHub, VPS ou ChatGPT.

### Higienizacao e rollback

O ramo ativo continua isolado. Manter o PR #305 como draft; nao fazer merge nem alterar a politica sem autorizacao real do proprietario e prova funcional de MCP. Preservar todos os certificados, Evidence, Unknowns, backups e ledger. Os testes offline nao criaram pedidos consumiveis no GitHub nem ficheiros persistentes na VPS. Os testes temporarios correram no runner do Actions.

## P311 - botao GitHub autenticado: verificacao isolada, SEM ativacao na VPS

- Foi preparado um **preview de aprovacao no proprio GitHub Actions**, usando a API oficial de revisoes de deployments e o ambiente `rea-p311-owner-consent`. Ficheiros: `ops/rea_p311_owner_gate_20261026.py`, `ops/tests/test_rea_p311_owner_gate_20261026.py` e `.github/workflows/rea-p311-owner-review-preview-20261026.yml`.
- Este preview e acionado SOMENTE pelo commit de um unico pedido novo em `rea-linux/owner-review-requests/<32hex>.json` no ramo de revisao. O pedido publico possui apenas identificador aleatorio, hash SHA-256, projeto REA e expiracao ate uma hora. Nao contem chave privada, grant, alvo privado ou comando.
- O workflow de revisao corre com `contents: read`, `actions: read`; nao contem SSH, segredo VPS, ferramentas REA, comandos de producao, permissoes de escrita ou motores adicionais.
- O job de aprovacao exige `environment: rea-p311-owner-consent`. O validador consulta via GitHub REST o workflow run e o respetivo review history: run ID, SHA, nome e ID estavel da conta de proprietario, branch, caminho do workflow, tentativa numero 1, ambiente correto e UM `approved` explicito para a mesma execucao. Recusas, falta de revisao, identidade falsa, outros projetos, expiracao ou repeticoes sao rejeitados.
- O resultado e **somente uma prova PREVIEW** e nunca e tratado como autorizacao de executar uma ferramenta sensivel ou como substituto da prova Ed25519 existente. A aprovacao pelo botao ainda NAO foi demonstrada ao vivo.

### Configuracao unica necessaria no GitHub (ainda nao efetuada)

Na pagina `https://github.com/martaxi-boss/VPS/settings/environments`, criar o ambiente `rea-p311-owner-consent`, definir `Required reviewers` para a conta `martaxi-boss` e desativar o bypass de administradores. Se a unica pessoa responsavel for tambem quem inicia o workflow, `Prevent self-review` NAO pode estar ligado; senao o proprio GitHub impede o seu botao de aprovar. Depois, o GitHub apresenta `Review deployments` e `Approve and deploy` ou a opcao de rejeitar. **Criar um ambiente sem `Required reviewers` NAO equivale a autorizacao.**

Documentacao oficial: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments e https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments.

O conector GitHub disponivel nesta sessao nao tem operacoes de administracao de ambientes/protection rules; nao afirmar que a configuracao foi efetuada ou que o owner clicou no botao. O codigo permanece num PR draft, sem merge nem alteracoes na VPS; esta configuracao unica e indispensavel para a prova visual de aprovacao.

## P311 - comprovacao REAL do botao GitHub e vinculo SHA a tarefa (2026-10-26)

**Este registo substitui as referencias anteriores de 'botao ainda nao demonstrado' e 'environment ainda nao configurado'.**

### Aprovacao real, comprovada via GitHub

- Run oficial: https://github.com/martaxi-boss/VPS/actions/runs/40385975218
- GitHub API: `status=completed`, `conclusion=success`, `head_sha=702c232bf3840ad55aae5b3847c1129ea375209f`, `run_attempt=1`.
- Review API: `state=approved`, `user.login=martaxi-boss`, `user.id=277365554`, `environment.name=rea-p311-owner-consent`, `environment.id=25387773772`.
- O job privado de preview confirmou `REA_P311_AUTHENTICATED_GITHUB_BUTTON_PREVIEW=PASS`, `REA_P311_OWNER_PERMISSION_REGISTERED=false`, `REA_P311_VPS_CHANGED=false`.
- Confirma que o owner clicou num botao real `Approve and deploy` e que a identidade foi revalidada no GitHub via API; NAO confirma Ed25519 assinado ou permissao operacional.
- Higienizacao ja aplicada: commit `7aa536a52fd2e87d5ff32a46925dfdd0390e6434` removeu o unico pedido publico `rea-linux/owner-review-requests/9e5a52a1742b2e0b8146f5293bfa0e1a.json` sem apagar a prova do run; nenhum pedido pendente.

### Vinculacao a um trabalho assinavel, ainda isolada

- Com o codigo de revisao P311, `signed_task_review_digest` calcula SHA-256 com separacao de dominio sobre **o conteudo integral da autorizacao Ed25519** e o `request_id` unico, incluindo ferramentas, projeto, efeito, pasta, assinatura e expiracao.
- `prepare_owner_review_request` devolve somente `purpose`, `request_id`, `operation_sha256`, projeto publico e validade curta. O grant e a assinatura nao sao enviados ao repositorio publico: so o hash da operacao entra no pedido de revisao.
- `match_verified_review_to_signed_task` deteta tentativas de alterar o projeto, ferramentas, pasta, efeitos, expiracao, assinatura ou identificador do pedido APOS o clique. Esta funcao so devolve um **vinculo PREVIEW**, nao uma autorizacao de chamada MCP.
- O verificador de historico oficial tambem exige o identificador imutavel do ambiente GitHub `25387773772`, alem do nome e da identidade do owner.
- Prova em CI sem VPS ou credenciais reais: **132/132 testes PASS** em https://github.com/martaxi-boss/VPS/actions/runs/40388611358.

### Estado e limites a respeitar

- O modo P311 continua desligado na VPS; a ponte operacional permanece no commit original `2f5573be27302f22aca5b9b3e20d78244f3ad0dc`.
- As 229 ferramentas originais e o estado Evidence/Unknowns/certificados/backups nao foram alterados.
- O clique GitHub NAO gera uma assinatura Ed25519 e o 'recibo preview' nao e um token de permissao autenticado por si so. Antes da ligacao a `sealed_task_enroll` ou `tools/call` no ambiente ativo, validar o dono e a politica com garantia independente, confirmar uma assinatura real para o scope aprovado e fazer teste MCP seguro, verificando rollback.
- PR #305 permanece draft e isolado, sem merge ou permissoes automáticas ativadas. Nao repetir ensaio do botao nem pedir nova confirmacao so para provar o mesmo passo.

## P311 — resultado desta continuidade: 150 testes e prova GitHub OIDC isolada

- **150/150 testes PASS, no GitHub Actions**, run `40391492310`: https://github.com/martaxi-boss/VPS/actions/runs/40391492310. Foram testes offline com pares RSA/Ed25519 efemeros; nenhum JWT real do proprietario foi usado ou armazenado.
- Ponto corrigido no bridge experimental: `sealed_task_enroll` agora exige a captura de resposta cifrada **ANTES** de validar/consumir nonce ou gravar a concessao assinada. Um erro neste ponto deixa a area privada intacta.
- A nova funcao `verify_and_bind_github_owner_review` obriga a comprovar conjuntamente a identidade da revisao REAL via API do GitHub e a hash do documento Ed25519 do mesmo trabalho. O clique de demonstracao anterior (run `40385975218`) NAO e validado como autorizacao de qualquer outro grant.
- Criado `ops/rea_p311_github_oidc_20261026.py` apenas no PR, ainda NAO integrado nos workflows de producao nem na ponte que executa o REA. Verifica assinatura RSA RS256 de OIDC JWT emitido pelo GitHub, issuer oficial, `kid` de JWKS oficial fixado, identidade imutavel do owner/repo, ambiente aprovado, workflow/ref, branch, run ID, SHA, audiencia ligada ao hash do mesmo trabalho e validade de poucos minutos.
- Os testes de OIDC recusam assinatura adulterada, algoritmos alternativos, endereco de chaves externo em header, review falso, owner incorreto, repo ID diferente, ambiente diferente, outro commit/run, expiração, audiencia trocada e atividade de outro workflow.
- O documento oficial de descoberta confirma issuer `https://token.actions.githubusercontent.com`, JWKS `https://token.actions.githubusercontent.com/.well-known/jwks` e `RS256`: https://token.actions.githubusercontent.com/.well-known/openid-configuration. Referencia de claims: https://docs.github.com/en/actions/reference/security/oidc.

### Distincao de garantia (critica)

- **Foi comprovado com a pessoa real:** botao GitHub `Approve and deploy`, identidade `martaxi-boss` e sucesso no run `40385975218`. Ja estava concluido e NAO foi repetido.
- **Foi comprovado agora apenas em testes offline:** combinacao review + JWT OIDC assinado + hash do grant Ed25519; as chaves RSA e Ed25519 sao efemeras e sinteticas. Nenhum JWT OIDC real de um job protegido foi emitido nesta fase.
- **Ainda nao se executou:** passar uma prova OIDC real no envelope cifrado para o servidor, autenticar e gastar `jti`/nonce exatamente uma vez, validar a autorizacao Ed25519 de politica e executar uma ferramenta sensivel real com rollback. Portanto, nao considerar o botao pronto para autorizar ferramentas de producao.
- O verificador OIDC nao devolve permissoes de ferramentas e nao substitui Ed25519. O modo P311 continua desligado na VPS, nao houve deploy nem alteracao de Evidence, Unknowns, certificados, backups ou ledger.

### Higienizacao

O PR #305 permanece DRAFT no ramo de revisao. Nao foi publicado qualquer novo pedido de aprovacao, token, chave ou grant. O ultimo pedido publico demonstrativo ja tinha sido eliminado e a prova do Actions ficou preservada. Evitar novos ensaios reais do botao ate que a integracao OIDC + grant Ed25519 esteja testada e estritamente circunscrita.

## P311 - verificacao real OIDC no proximo review, 163 testes offline

- **CI P311 163/163 PASS** no run https://github.com/martaxi-boss/VPS/actions/runs/40393431413. Prova somente offline, sem uso do motor ou da VPS nesta execucao.
- Foi preparada, no `rea-p311-owner-review-preview-20261026.yml`, a obtencao de um token OIDC GitHub autenticado **apenas depois** do botao num ambiente protegido. `id-token: write` esta no job protegido, nao no workflow todo; nao inclui SSH, acesso ao REA, chamada MCP, chave privada, grant ou permissao de escrita no repositorio.
- A verificacao real via CLI `python -m ops.rea_p311_github_oidc_20261026` confere via REST HTTPS a aprovacao explicita do owner, confere `run_id`, commit SHA, branch, workflow, reviewer/ambiente, pede um token OIDC com AUDIENCE especifica por `request_id` + digest, valida JWT RSA RS256 com JWKS do emissor oficial e NAO imprime nem armazena token ou bearer em logs.
- O URL para solicitar identidade aceita somente endpoints oficiais `https://pipelines*.actions.githubusercontent.com/.../idtoken?api-version=2.0`, sem redirecionamento, host alternativo, porta arbitraria, audiência preexistente ou credencial em URL. A versao Python de `cryptography` do venv do runner foi fixada em 46.0.3 para reduzir alteracoes externas.
- O helper de replay `verify_owner_review_oidc_and_consume_once` so funciona apos validar JUNTAMENTE GitHub review + JWT do GitHub + concessao Ed25519 com os efeitos de ferramentas fonte-auditados + revogacao. Regista o `request_id` **uma unica vez** num diretorio privado PRE-provisionado (0700) com marcador de criacao atomica (0600) e O_EXCL/O_NOFOLLOW; nao grava o JWT nem a assinatura do owner.
- Testes cobrem JWT forjado ou expirado, reviewer diferente, origem OIDC externa, consentimento de outro projeto, assinatura Ed25519 errada, revogacao, diretorio em falta/symlink/modo inseguro, replay de pedido e ausencia de leaks em recibos.

### Separar claramente prova de teste, consentimento e producao

- O clique **real** do owner continua comprovado no run https://github.com/martaxi-boss/VPS/actions/runs/40385975218. O OIDC **real** ainda nao foi emitido nem testado: a nova etapa OIDC de runner so correra com uma **futura** revisao autorizada pelo dono num novo pedido, nao podendo obter prova retroativa do run anterior.
- Mesmo quando o OIDC de runner passar num futuro review, **nao substitui** a assinatura Ed25519 para autorizar ferramentas sensiveis; o owner assina uma concessao delimitada uma vez por tarefa na configuracao atual.
- Nao foi criado novo pedido de GitHub review; nenhum novo clique foi pedido nesta continuacao. PR #305 continua DRAFT, o motor original 6.8.0 intacto, o ramo ativo sem deploy nem restart, e `REA_P311_SCOPED_TASKS` DESLIGADO.
- A marcacao como consumido foi apenas ensaiada em ficheiros temporarios do Actions: ainda nao esta ligada a autorizacao de tools/call nem a persistencia real da VPS.

### Proxima integracao

Para ativar esta protecao na VPS e necessario emitir autorizacao REAL limitada e validada do proprietario, completar leitura autenticada do review/JWT pelo servidor e reconciliar o replay ledger com registro de grants sob revisao e rollback. Nao transformar o sucesso do preview num falso `approved=true`.


## P311 - Fase A: origem do pedido GitHub e ledger antirreplay duravel (26/10/2026)

- **165/165 testes offline PASS** em https://github.com/martaxi-boss/VPS/actions/runs/40396101036, para o commit de codigo e testes da4736df1983bcc197a1c5c0b2eb3847c14b8653. Nao houve SSH/VPS nem operacao MCP neste run.
- verify_committed_review_request passou a ser obrigatoria antes de verify_owner_review_oidc_and_consume_once: o commit REST de origem confiavel tem de ser o mesmo head_sha do run, adicionar SOMENTE o ficheiro de desafio aprovado, e os bytes exatos do blob Git SHA-1 devem coincidir com o pedido publico e a pasta/ID. Adulteracoes e trocas de commit/blob/pedido falham antes de consumir a autorizacao.
- O contexto do commit, os metadados e o blob devem ser obtidos futuramente por um cliente de API GitHub DE CONFIANCA, com SHA exato e repositorio fixado; nao aceitar objetos fornecidos por payloads MCP nem parametros do utilizador. O modulo isolado nao cria esse cliente na VPS nem demonstra esta ligacao real.
- O marcador privado de uso unico usa descriptors ancorados ao diretorio-pai e filho 0700, O_DIRECTORY/O_NOFOLLOW, O_EXCL, ficheiro 0600, fsync do ficheiro e do diretorio. Testes validam estas chamadas, rejeicoes e consumo unico; nao constituem prova de recuperacao apos falha fisica do disco.
- A primeira CI do commit 4eb6607f06c963fc805fd1255f419ed3128470ff identificou que um teste de assinatura invalida passou a ser barrado antes pela verificacao do blob. O caso foi ajustado para fornecer o commit e o desafio sinteticos coerentes e voltou a comprovar a rejeicao da assinatura Ed25519 falsa no CI verde posterior.
- O modulo continua somente em PR DRAFT; as 165 verificacoes usam chaves sinteticas e fixtures temporarias do Actions. Nao foi emitido JWT OIDC real de job protegido, nao houve nova revisao humana, nao foi criado pedido publico de aprovacao, nao foi registado grant real, nao houve merge, deploy, restart nem alteracao ao motor REA original.
- Proxima porta: ensaio OIDC real com novo pedido e aprovacao humana autenticada quando preparado e consentido; so depois integrar metadados GitHub confiaveis e assinatura Ed25519 real no registo seguro, preservar rollback e ensaiar MCP sensivel reversivel sob autorizacao.


## P311 - Fase A concluida offline: 169 -> 170 -> 173 testes (26/10/2026)

### Ligacao GitHub REST de origem confiavel, 169/169 PASS

- Commit `b41943a2ec346082ced68e27481d3b59ab84f371`, CI https://github.com/martaxi-boss/VPS/actions/runs/40397751220 : **169/169 testes offline PASS**.
- O adaptador `fetch_trusted_owner_review_evidence` obtem a partir de URLs **fixadas ao repositorio VPS**: run por ID, revisoes por run, commit pelo `head_sha` aprovado, e blob por SHA do unico ficheiro de desafio adicionado. Verifica repo e ID imutavel, ator e triggering actor, dados REST, hash real dos bytes do blob e review no ambiente protegido. Nao aceita o branch tip ou metadados publicos escolhidos pelo pedido.
- `verify_trusted_owner_review_oidc_and_consume_once` combina esta evidencia com o validador JWT do emissor fixado, scope Ed25519 auditado, revogacao e ledger de uso unico. Este novo ponto de entrada **nao** esta ligado a `tools/call`, SSH/VPS ou execucao de ferramentas REA.
- A consulta read-only dos metadados historicos de `40385975218` confirmou que o GitHub devolve `repository/head_repository` com IDs corretos, owner, ambiente e review real. Aprovacao antiga **nao foi reutilizada** e o token OIDC real ainda nao foi emitido.

### Workflow com falha nao autoriza: 170/170 PASS

- Commit `3cb28151afd2967b7dd5d216864218254cde158d`, CI https://github.com/martaxi-boss/VPS/actions/runs/40398416021 : **170/170 PASS**.
- O **consumo no servidor** exige `status=completed` e `conclusion=success` no run GitHub. Jobs pendentes, falhados, cancelados, skipped ou sem conclusao recusam antes de consultar reviews, emitir registos ou gastar uma prova. O preview OIDC dentro do job protegido mantem a sua validacao autonoma antes do final do workflow.

### Registo privado apos consentimento: 173/173 PASS

- Commit `dcc97f2cb2b1157ccaad007330f8906a64d2d9b9`, CI https://github.com/martaxi-boss/VPS/actions/runs/40398811668 : **173/173 PASS**.
- `enroll_trusted_reviewed_task_offline_only` encadeia a leitura segura de provas GitHub, verificacao conjunta do JWT do job e grant Ed25519, comprovacao de nao revogacao, consumo unico e **registo privado experimental**. Exige registo privado PREEXISTENTE; nunca cria a pasta devido a um pedido publico.
- A sequencia e deliberadamente fail-closed: um erro ao gravar o registo **apos** a prova ser marcada como consumida nao reabre a mesma autorizacao, nem cria permissao de ferramentas. Uma recuperacao exigira um novo pedido assinado e aprovado, nao um retry silencioso.
- Testes negativos cobrem falta de diretorio privado, tentativa de repeticao e falha simulada de disco; o CI usa apenas ficheiros temporarios e chaves sinteticas. Nao foram escritos grants reais na VPS.

### Fronteira de seguranca que continua obrigatoria

- **OIDC real de job protegido: nao executado**. A demonstracao do botao real `40385975218` foi anterior e nao prova a nova emissao OIDC.
- O codigo continua num PR #305 DRAFT, isolado da ponte operacional. `REA_P311_SCOPED_TASKS` permanece OFF na VPS; nenhum merge, SSH, deploy, restart, chamada MCP sensivel, modificacao ao REA original, certificado, Evidence, Unknowns, ledger ou backup.
- Antes de qualquer teste real, e indispensavel uma **concessao Ed25519 real e limitada** assinada no Android e um **novo** desafio SHA-256 correspondente, seguido de nova aprovacao autenticada no ambiente protegido e comprovacao JWT; a aprovacao historica nao serve. Nao publicar grant/JWT ou chave privada.
- A integracao produtiva e rollback ainda nao estao comprovados. A proxima fase nao pode declarar operacionais as 47 ferramentas sensiveis por delegacao.
