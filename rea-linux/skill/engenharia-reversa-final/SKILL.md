---
name: engenharia-reversa-final
description: Skill principal da caixa de ferramentas REA FINAL em Ubuntu Linux. Usar automaticamente em pedidos de engenharia reversa, auditorias, leitura, programacao, construcao, alteracao, testes, websites, criativos e trabalho tecnico nos projetos do utilizador, mesmo sem @REA. O ChatGPT ou Codex compreende, planeia e conversa normalmente, mas executa primeiro com ferramentas reais MCP do REA; usa ferramentas proprias apenas para capacidades que o REA nao consiga executar. Nao alterar a ponte SSH.
---

# Engenharia Reversa FINAL - uma Skill, um motor, competencias crescentes

**Objetivo:** esta Skill e a entrada preferencial para a caixa de ferramentas pessoal do utilizador. A inteligencia externa (atualmente ChatGPT; no futuro outro cliente de IA configurado) compreende, planeia, coordena e interpreta. O REA instalado no Ubuntu e o executor tecnico principal. Nao transformar a Skill num segundo motor ou num catalogo inventado.

## Regra dominante: mesmo ChatGPT, executor REA

- Conversar naturalmente com o utilizador, como num chat normal. A IA compreende, raciocina, planeia e interpreta resultados. **A execucao tecnica deve passar primeiro pelo REA**: ler, investigar, editar, criar, programar, compilar, testar, auditar, operar e verificar, quando existe uma via MCP REA adequada e funcional.
- A Skill e a unica entrada; nao pedir ao utilizador para traduzir os pedidos em nomes de ferramentas, JSON ou comandos. A IA escolhe as chamadas entre os contratos MCP realmente publicados pelo REA, com argumentos validos. O motor e os programas nele integrados executam.
- Para cada etapa de trabalho, preferir uma ferramenta MCP especifica quando corresponder ao pedido; `capture_process_scenario` e uma ferramenta REA legitima para operacoes Linux e programas locais, mas nao deve mascarar uma ferramenta REA mais apropriada nem ser confundida com analise especializada.
- Nao substituir por ferramentas do ChatGPT, Codex ou GitHub o trabalho que o REA conseguir efetivamente fazer, apenas por comodidade. O acesso GitHub usado para levar o pedido MCP e recuperar a resposta e **transporte**, nao um executor alternativo.
- Quando faltar uma capacidade ou fornecedor operacional, tentar resolver primeiro a chamada/ambiente dentro das capacidades existentes do REA. Se nao houver caminho funcional, usar as ferramentas proprias da IA somente nessa parte, indicar a origem e regressar ao REA nas outras etapas. Nao inventar competencias nem repetir tentativas sem progresso.
- Responder normalmente a perguntas apenas conversacionais sem forcar execucao tecnica desnecessaria. Quando o utilizador pedir trabalho tecnico, tentar efetivamente o REA e nao ficar por um plano ou por uma resposta generica.

## Entrada e ativacao

- Se esta Skill estiver instalada e disponivel, aplicar automaticamente a pedidos relevantes de trabalho tecnico, mesmo sem invocacao explicita. Isto depende da descoberta de Skills do cliente; nao prometer ativacao incondicional em todos os chats ou em outros ambientes sem instalacao propria.
- A IA externa escolhe chamadas **MCP reais** com base nas capacidades publicadas pelo motor; o REA executa as operacoes e usa os fornecedores instalados quando as ferramentas suportam essa escolha. O REA nao e, por si, outra IA que interpreta todos os pedidos livres.
- Nao confundir a preferencia pelo REA com a obrigacao de usar uma ferramenta inadequada: APKTool nao cria websites so por estar instalado. A selecao e por capacidade e adequacao ao pedido.

## Principio REA primeiro, alternativa explicita

1. Compreender o objetivo e identificar os trabalhos necessarios, sem executar fora do REA por conveniencia.
2. Consultar `tools/list` e, quando relevante, disponibilidade, contratos, fornecedor e dependencias reais. Ferramenta anunciada nao e sinonimo de ferramenta funcional ou certificada.
3. Escolher e **executar pelo REA** toda a tarefa suportada e operacional, usando o MCP nativo. Aproveitar os fornecedores e dependencias existentes no runtime; nao criar instalacoes repetidas para cada projeto.
4. Se faltar capacidade apropriada, distinguir ausencia real de uma chamada mal formada, erro de permissao do projeto ou falha recuperavel. Corrigir o uso legitimo da ferramenta REA primeiro; so apos confirmar a lacuna comparar a alternativa da propria IA e aplica-la apenas a essa parte. Identificar explicitamente o que foi feito fora do motor.
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
3. Separar resultado do transporte, resposta MCP e resultado de **cada verificacao interna**. GitHub Actions verde, `result.isError=false` ou `exit.code=0` **nao provam** que todos os comandos passaram. Para `capture_process_scenario`, ler `structuredContent.normalized_result.exit.code`, `frames`, `settlement`, `cleanup` e `truncation_details`, verificar mensagens de erro e marcadores de cada etapa. Dizer PARCIAL/FALHA quando um subteste falhou ou nao foi comprovado.
4. Numa auditoria, mapear as areas pedidas e cobrir efetivamente cada uma; verificar backend, frontend, dados, servicos e testes conforme aplicavel. Uma analise AST nao e uma auditoria semantica completa; relatar cobertura insuficiente.
5. Apresentar evidencias e limites por ferramenta, fornecedor e fase. Nao instalar programas adicionais nem alterar projetos externos sem pedido do utilizador.

## Ajustes derivados do teste real no Low Cost Europa

- Evitar mascarar falhas com `set +e`, `|| true` ou pipelines sem verificar o codigo de saida de cada comando importante. Um `fatal:`, `Permission denied` ou uma validacao negativa no terminal nao vira PASS por o script terminar com `exit 0`.
- Consultar repositorios da VPS com a identidade proprietaria adequada (por exemplo `sudo -n -u <conta-do-projeto> git ...`, quando disponivel), em vez de alterar `safe.directory` global para ocultar um problema de propriedade.
- Confirmar HTTPS/TLS sem `curl -k` ao certificar o certificado. Se uma tentativa insegura ocorreu, classificar essa tentativa como nao comprovada e repetir corretamente.
- Diferenciar truncagem da representacao renderizada de perda efetiva de bytes brutos (`truncation_details.raw_terminal`). Quando `settlement.state=unverifiable`, explicar a incerteza observacional mesmo se o comando terminou com codigo zero; isto nao significa automaticamente que a operacao falhou.
- Separar a autoria e execucao: operacoes feitas pelo REA, tarefas nativas GitHub/CI e qualquer fallback executado pela IA. A validacao do CI nao prova por si que o REA escreveu o codigo. Antes de declarar auditoria completa, demonstrar a cobertura realmente percorrida, nao so `tools/list` nem AST.

## Provas reais anteriores

- [41051659568](https://github.com/martaxi-boss/VPS/actions/runs/41051659568): arranque local autonomo REA MCP, catalogo de 229 ferramentas anunciadas, chamada real e exit zero.
- [41055616293](https://github.com/martaxi-boss/VPS/actions/runs/41055616293): auditoria REA ao Low Cost Europa, incluindo teste negativo em que Actions e MCP responderam mas o comando interno terminou com exit 17; nao confundir os estados.
- [41059587838](https://github.com/martaxi-boss/VPS/actions/runs/41059587838): validacao de ponta a ponta de 229 ferramentas anunciadas, chamadas MCP reais, fornecedores locais e exit 0; a ponte e o workflow nao foram alterados.

Ver `references/metodologia.md`, `references/ambiente_final.md`, `references/ponte_operacional.md` e `references/relatorio.md`.