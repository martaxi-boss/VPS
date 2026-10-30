---
name: engenharia-reversa-final
description: Porta de entrada da caixa de ferramentas pessoal REA FINAL em Ubuntu Linux. Usar automaticamente quando disponivel e o pedido envolver auditoria, analise, programacao, websites, criativos ou outras tarefas tecnicas para a caixa de ferramentas, mesmo sem @REA explicito. A IA externa planeia e conduz; consultar primeiro o catalogo MCP real e executar prioritariamente pelo motor REA; recorrer a ferramentas proprias da IA somente quando nao houver capacidade REA apropriada e disponivel, identificando a diferenca.
---

# Engenharia Reversa FINAL - uma Skill, um motor, competencias crescentes

**Objetivo:** esta Skill e a entrada preferencial para a caixa de ferramentas pessoal do utilizador. A inteligencia externa (atualmente ChatGPT; no futuro outro cliente de IA configurado) compreende, planeia, coordena e interpreta. O REA instalado no Ubuntu e o executor tecnico principal. Nao transformar a Skill num segundo motor ou num catalogo inventado.

## Entrada e ativacao

- Se esta Skill estiver instalada e disponivel, aplicar automaticamente a pedidos relevantes de trabalho tecnico, mesmo sem invocacao explicita. Isto depende da descoberta de Skills do cliente; nao prometer ativacao incondicional em todos os chats ou em outros ambientes sem instalacao propria.
- A IA externa escolhe chamadas **MCP reais** com base nas capacidades publicadas pelo motor; o REA executa as operacoes e usa os fornecedores instalados quando as ferramentas suportam essa escolha. O REA nao e, por si, outra IA que interpreta todos os pedidos livres.
- Nao confundir a preferencia pelo REA com a obrigacao de usar uma ferramenta inadequada: APKTool nao cria websites so por estar instalado. A selecao e por capacidade e adequacao ao pedido.

## Principio REA primeiro, alternativa explicita

1. Compreender o objetivo e identificar os trabalhos necessarios, sem executar fora do REA por conveniencia.
2. Consultar `tools/list` e, quando relevante, disponibilidade, contratos, fornecedor e dependencias reais. Ferramenta anunciada nao e sinonimo de ferramenta funcional ou certificada.
3. Escolher e **executar pelo REA** toda a tarefa suportada e operacional, usando o MCP nativo. Aproveitar os fornecedores e dependencias existentes no runtime; nao criar instalacoes repetidas para cada projeto.
4. Se uma capacidade faltar, estiver indisponivel, falhar ou nao for apropriada, fazer comparacao concreta: operacao pretendida; capacidades existentes no REA; lacuna e prova; alternativa disponivel na propria IA; impacto na qualidade. Usar essa alternativa apenas para a parte que nao pode ser executada pelo REA. Indicar claramente que parte foi feita fora do motor.
5. Retomar o REA nas partes seguintes sempre que tiver a competencia adequada. Nao declarar que o REA realizou trabalho feito pelo ChatGPT, pelo conector GitHub, por CI ou por outra ferramenta.
6. Reportar o que foi realmente realizado, com ferramentas, fornecedores usados, IDs de execucao, cobertura e lacunas, distinguindo **PASS, PARCIAL e FALHA** por operacao.

## Crescimento gradual da caixa de ferramentas

- Os novos candidatos devem ser projetos/ferramentas existentes e verificaveis no GitHub, selecionados conforme as necessidades do utilizador. Antes de integrar, comparar funcao, licenca, compatibilidade com Ubuntu e arquitetura, dependencias, versoes, fornecedor, seguranca operacional e possibilidade real de integracao com o REA.
- Reutilizar Java, Frida, Ghidra, JADX, Hydra ou qualquer outra dependencia **apenas se efetivamente instalada e compatibilidade confirmada**; nao pressupor que a presenca de um nome no catalogo prova instalacao ou funcionamento. Isolar somente versoes incompatíveis quando necessario.
- Integrar e testar cada competencia antes de a declarar operacional. Uma instalacao de programa nao cria automaticamente uma nova ferramenta MCP. Se o REA precisar de evolucao para integrar determinada competencia, estudar uma alteracao controlada e versionada do motor pessoal, mantendo a versao funcional preservada. **Nao modificar o motor original atual sem pedido especifico e teste.**
- Nao criar novo motor, MCP, workflow, camada de decisao ou coordenador apenas para acrescentar competencias. A Skill continua unica; o catalogo e as ferramentas do motor evoluem conforme implementacoes reais.

## Instalacao e ligacao existente

- REA original atual: `morluto/rea` pacote `rea-agents 6.8.0`, commit `160d821ac9a0310afcb8d1fc427862dd6508add5`; instalacao `/home/ubuntu/rea-original-upstream-680`.
- Runtime pessoal independente: `/home/ubuntu/rea-final-runtime`, com arranque `/home/ubuntu/rea-final-runtime/bin/rea-mcp` e fornecedores locais. O motor atual nao foi alterado.
- Transporte atual: GitHub `martaxi-boss/VPS`, branch `rea/one-skill-bridge-20261023`, workflow existente `.github/workflows/rea-mcp-transport-20261027.yml`, SSH e `rea-linux/skill-bridge/execute_request.py`. A ponte apenas entrega mensagens MCP e devolve respostas; nao decide ferramentas, fornecedores ou regras de auditoria.
- O mesmo comando local MCP pode ser utilizado por outro cliente compativel, com configuracao propria nesse cliente; migrar de ChatGPT para Codex nao exige duplicar fornecedores no motor. Nao presumir que a Skill se instala automaticamente em Codex ou Claude.
- Norma permanente versionada: `rea-linux/runtime/OPERATIONS.md`. Pormenores do transporte em `references/ponte_operacional.md`.

## Execucao verificavel

1. Ler `rea-linux/skill-requests/current.json` e respetivo blob SHA, atualizar com `request_id` unico e `mcp_requests` MCP nativos, num commit `skill-request: <request_id>` na branch indicada. Isto aciona o workflow ja existente. Operacoes que partilham estado devem estar na mesma sessao.
2. Associar o run ao **commit SHA** criado, ler o job `engenharia-reversa-skill` e reconstruir `REA_MCP_RESULT_PART=N/T:` em ordem se houver fragmentos. Confirmar `request_id`, numero de fragmentos e integridade do JSON.
3. Separar resultado do transporte, sucesso MCP e resultado da operacao. Um GitHub Actions verde ou `result.isError=false` **nao prova** a execucao interna. Para `capture_process_scenario`, consultar `result.structuredContent.normalized_result.exit.code`, `settlement`, `cleanup` e truncation. Exit diferente de zero e falha interna mesmo que o run seja verde.
4. Numa auditoria, mapear as areas pedidas e cobrir efetivamente cada uma; verificar backend, frontend, dados, servicos e testes conforme aplicavel. Uma analise AST nao e uma auditoria semantica completa; relatar cobertura insuficiente.
5. Apresentar evidencias e limites por ferramenta, fornecedor e fase. Nao instalar programas adicionais nem alterar projetos externos sem pedido do utilizador.

## Provas reais anteriores

- [41051659568](https://github.com/martaxi-boss/VPS/actions/runs/41051659568): arranque local autonomo REA MCP, catalogo de 229 ferramentas anunciadas, chamada real e exit zero.
- [41055616293](https://github.com/martaxi-boss/VPS/actions/runs/41055616293): auditoria REA ao Low Cost Europa, incluindo teste negativo em que Actions e MCP responderam mas o comando interno terminou com exit 17; nao confundir os estados.

Ver `references/metodologia.md`, `references/ambiente_final.md`, `references/ponte_operacional.md` e `references/relatorio.md`.