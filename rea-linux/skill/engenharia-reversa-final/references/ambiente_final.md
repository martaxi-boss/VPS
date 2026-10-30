# Ambiente FINAL preservado

Motor do autor: `morluto/rea`, commit `160d821ac9a0310afcb8d1fc427862dd6508add5`, pacote `rea-agents 6.8.0`.

VPS Linux atual:
- Motor: `/home/ubuntu/rea-original-upstream-680`.
- Runtime independente: `/home/ubuntu/rea-final-runtime`.
- Arranque autonomo: `/home/ubuntu/rea-final-runtime/bin/rea-mcp`.

A configuracao dos fornecedores Node, JDK, Ghidra, JADX, Binwalk e outros programas compativeis faz parte da instalacao REA, e nunca do ficheiro do transporte. A migracao para workstation Ubuntu requer copiar/reinstalar as dependencias compativeis e comprovar o MCP diretamente. Nao misturar com a instalacao antiga em `/opt/rea-reversa`.

GitHub: `martaxi-boss/VPS`, branch `rea/one-skill-bridge-20261023`, pasta `rea-linux/runtime/` para o arranque portatil e guias.

Prova local pela VPS: Actions 41051659568, REA_DIRECT_LOCAL_MCP=pass, REA_DIRECT_TOOLS=229, REA_DIRECT_CALL=pass, codigo de saida 0. A prova foi desencadeada remotamente, mas o segundo processo MCP foi aberto pelo comando local instalado, sem configuracao de fornecedores do transporte.

Uma analise JavaScript estatica nao equivale a auditoria de Django/Python, nem comprova uso de Ghidra, JADX, fornecedores pagos ou todas as ferramentas listadas.
