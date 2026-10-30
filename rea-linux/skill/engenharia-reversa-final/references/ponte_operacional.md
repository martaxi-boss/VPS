# Transporte MCP original: ChatGPT / Codex compatível → VPS

Esta referência descreve apenas **como comunicar com o REA original**. Não define ferramentas REA novas, operações de engenharia reversa, políticas de fornecedores ou outra IA.

## Destino único

- Motor: `/home/ubuntu/rea-original-upstream-680/scripts/rea.mjs mcp` (versão do autor 6.8.0, commit `160d821ac9a0310afcb8d1fc427862dd6508add5`).
- Runtime independente: `/home/ubuntu/rea-final-runtime`.
- Repositório: `martaxi-boss/VPS`; branch `rea/one-skill-bridge-20261023`.
- Workflow **existente**: `.github/workflows/rea-mcp-transport-20261027.yml`.
- Pedido: `rea-linux/skill-requests/current.json`.
- Transporte: `rea-linux/skill-bridge/execute_request.py` (cliente stdio MCP simples, enviado pelo SSH já autenticado).

## Formato do pedido

O objeto contém somente `request_id` (único) e `mcp_requests` (lista não vazia). Cada elemento é uma mensagem de pedido MCP com `method` e `params` opcionais. O transporte inicia o MCP do REA, envia `initialize`, envia `notifications/initialized`, e encaminha cada pedido ao mesmo processo MCP na ordem recebida.

Consultar ferramentas:

```json
{"request_id":"rea-list-20261030-001","mcp_requests":[{"method":"tools/list","params":{}}]}
```

Chamar uma ferramenta já identificada:

```json
{"request_id":"rea-call-20261030-001","mcp_requests":[{"method":"tools/call","params":{"name":"inspect_analysis_settings","arguments":{}}}]}
```

Sequência no mesmo alvo e na mesma sessão MCP:

```json
{"request_id":"rea-artifact-20261030-001","mcp_requests":[{"method":"tools/call","params":{"name":"open_binary","arguments":{"path":"/caminho/autorizado/exemplo.apk"}}},{"method":"tools/call","params":{"name":"inspect_artifact","arguments":{"detail":"summary"}}}]}
```

A escolha de ferramentas pertence ao agente de IA e à descrição do catálogo MCP original. A escolha de fornecedor interno, quando automática, pertence ao REA. Não existem nomes de ferramentas impostos pelo transporte nem um limite artificial para o número de chamadas numa sessão. Os limites de recursos reais do GitHub, SSH e motor continuam a aplicar-se.

## Enviar e verificar

1. GitHub `fetch_file` do pedido na branch para obter o blob SHA.
2. GitHub `update_file` com o novo JSON, `sha` observado, branch indicada e commit message `skill-request: <request_id>`.
3. Consultar GitHub Actions desse **commit SHA**. Esperar a conclusão do job `engenharia-reversa-skill`.
4. Ler o log do job. O marcador `REA_SKILL_BRIDGE_RESULT=` contém `request_id`, `status` e `responses`. Em resposta grande, contém `parts`; os registos `REA_MCP_RESULT_PART=índice/total:trecho` transportam o JSON completo, sem perda de conteúdo. Ordenar, concatenar e fazer parse; verificar todos os índices e o `request_id`.
5. Considerar sucesso apenas se o job foi bem-sucedido e os resultados individuais de `tools/call` não indicam `isError` nem erro de protocolo.

**Ação não concluída ou resposta ausente não é PASS.** Não confundir sucesso do workflow com sucesso de outra ferramenta ou fornecedor.

## Testes de 30/10/2026

- [41035333062](https://github.com/martaxi-boss/VPS/actions/runs/41035333062): resposta MCP original para `inspect_analysis_settings`.
- [41035502436](https://github.com/martaxi-boss/VPS/actions/runs/41035502436): `tools/list` com 229 nomes e contratos + `tools/call` numa única sessão. Resultado original preservado em 587 partes de log, recompostas com sucesso.

**Nota:** a Skill é portátil como instrução. Outro chat/agente, como Codex Cloud, só utiliza esta VPS se também tiver acesso funcional e autorizado ao mesmo GitHub e workflow. Não é necessário instalar uma IA na VPS.
