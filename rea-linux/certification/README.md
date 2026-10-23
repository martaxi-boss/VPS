# Certificação funcional do motor REA em Linux

**Âmbito vinculativo:** o único motor REA continua instalado no servidor Linux existente, em `/opt/rea-reversa/rea`. Todas as operações de análise, fornecedores, resultados e testes de certificação são executados no Linux, sem dependência obrigatória de uma distribuição específica.

A ligação existente `ChatGPT -> GitHub Actions -> SSH -> VPS Linux -> MCP em 127.0.0.1:8765/mcp` é apenas transporte para comandar o motor instalado. A nomenclatura legada de certos ficheiros da ponte não determina o sistema operativo do motor. Não mudar ou remover a ponte operacional durante esta normalização.

## Aprovação canónica

Cada uma das 208 ferramentas tem um contrato funcional próprio. Para aprovar uma ferramenta, registar: nome MCP e schema real, finalidade, alvo controlado guardado no Linux, resultado de `tools/call` (incluindo `isError`), comparação com resultado esperado, SHA-256 quando aplicável, invariância da entrada, limpeza da sessão/ficheiros, dependências e limitações, commit e ID da execução Actions.

Estados permitidos: `NOT_REVIEWED`, `FUNCTIONAL_PASS_SCOPED`, `FULLY_CERTIFIED`, `PROVIDER_UNAVAILABLE`, `FAILED`, `AUTHORIZATION_REQUIRED`. Não confundir sucesso do transporte com correção funcional. Não aprovar uma ferramenta sem resultado demonstrado. Testes negativos são necessários antes da certificação completa.

## Continuação em fases

Primeiro reconciliar as evidências já obtidas no Linux, sem repetir ensaios. Depois selecionar ferramentas ainda não cobertas e testar por função; corrigir problemas numa área isolada; voltar a testar pelo MCP original; consolidar as provas neste diretório. A atividade de certificação não autoriza modificar, reiniciar ou reconfigurar o serviço de produção, nem instalar outro motor.

O ficheiro `functional-ledger.json` é o registo ativo. Evidências de execuções históricas continuam disponíveis nos respetivos commits e runs GitHub, mas não contam automaticamente como certificação funcional.
