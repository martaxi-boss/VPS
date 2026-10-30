# Transporte MCP substituivel - GitHub Actions + SSH atual

O transporte atual e uma forma de acesso, nao faz parte das dependencias do motor.

- Repositorio: `martaxi-boss/VPS`; branch `rea/one-skill-bridge-20261023`.
- Workflow ja existente: `.github/workflows/rea-mcp-transport-20261027.yml`.
- JSON de pedido: `rea-linux/skill-requests/current.json`.
- Cliente de transporte: `rea-linux/skill-bridge/execute_request.py`.
- Ponto de entrada do REA na VPS: `/home/ubuntu/rea-final-runtime/bin/rea-mcp`.

O objeto tem `request_id` unico e `mcp_requests` nao vazio, com mensagens nativas MCP, por exemplo:

```json
{
  "request_id": "rea-consulta-20261030-001",
  "mcp_requests": [
    {"method":"tools/list","params":{}},
    {"method":"tools/call","params":{"name":"inspect_analysis_settings","arguments":{}}}
  ]
}
```

1. Ler o ficheiro GitHub e guardar o blob SHA; usar `update_file` na mesma branch com commit `skill-request: <request_id>`.
2. Associar o run ao SHA do novo commit, nao a ordem temporal.
3. Ler o job `engenharia-reversa-skill`, depois `REA_SKILL_BRIDGE_RESULT=`. Se fragmentado, reconstituir `REA_MCP_RESULT_PART=N/T:` na ordem exata, verificar total e JSON.
4. O status geral da ponte confirma **entrega e resposta MCP**, nao o exit do processo interno. Ler sempre o `result.structuredContent` da ferramenta. Para captura de processos, exigir `normalized_result.exit.code == 0` e avaliar settlement/cleanup antes de declarar sucesso operacional.

Na migracao, esta referencia pode ser descartada. As configuracoes e os fornecedores continuam no runtime local do REA.
