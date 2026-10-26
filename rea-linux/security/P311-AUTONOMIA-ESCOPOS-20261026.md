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
