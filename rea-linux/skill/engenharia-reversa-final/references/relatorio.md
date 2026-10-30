# Relatorio minimo por tarefa da caixa REA

- Pedido, objetivo, alvo, commit/projeto e ambiente de execucao.
- Capacidades REA consultadas e disponibilidade efetivamente confirmada.
- Ferramentas MCP realmente usadas, porque foram escolhidas, e fornecedor/dependencia realmente executados; diferenciar ferramenta REA especializada de processo Linux executado pelo REA.
- Se houver fallback: qual a capacidade em falta no REA, tentativa de correccao do uso quando cabivel, comparacao com alternativa, qual a ferramenta propria da IA usada e resultado concreto; nunca chamar a esse trecho execucao REA.
- IDs de pedido MCP, commits e runs de transporte; diferenciar transporte, MCP e operacao tecnica.
- Para `capture_process_scenario`: `normalized_result.exit.code`, `settlement`, `cleanup`, `frames` e `truncation_details` (bruto vs renderizado). Verificar o sucesso de cada subcomando relevante; exit global zero nao torna subtestes falhados em PASS.
- Evidencia, cobertura, resultados PASS/PARCIAL/FALHA, limites e proximas lacunas.

`tools/list` anunciar 229 ferramentas nao significa certificar 229 ferramentas. Uma dependencia ou executavel instalado nao demonstra que o REA o utilizou.

## Teste negativo confirmado

Run 41055616293: GitHub Actions `success`, MCP `PASS`, mas quarto `capture_process_scenario` com `normalized_result.exit.code=17`. A operacao tecnica falhou deliberadamente; isso nao invalida o transporte mas nao e um PASS da tarefa. `settlement.state=unverifiable` tambem limita a certeza de observacao, mesmo com exit zero.

## Erros observados a distinguir

- `dubious ownership` ou `Permission denied`: o subteste Git nao passou, mesmo com exit global 0.
- `curl -k` e `ssl_verify=20`: certificado TLS nao validado nessa tentativa; repetir sem ignorar TLS.
- `settlement=unverifiable`: capacidade de observacao limitada, nao falha automatica do programa.
- Truncagem apenas renderizada: nao afirmar perda do terminal bruto se o proprio REA reteve os bytes brutos.
