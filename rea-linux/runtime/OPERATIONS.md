# Engenharia Reversa FINAL - norma de utilizacao independente de transportes

Esta norma acompanha a instalacao do REA no repositorio e numa workstation.
NAO pertence a GitHub Actions, SSH, Desktop Commander ou a outro transporte.
O motor original do autor permanece intacto. Nao criar outro MCP ou motor.

## Responsabilidades

- ChatGPT e a unica IA de decisao: interpreta a ordem, consulta o catalogo MCP
  do REA e escolhe operacoes pertinentes com base nos contratos publicados.
- REA original: executa as operacoes MCP e utiliza os fornecedores instalados
  quando suportados. Nao duplicar logica de analise ou seletores de fornecedores.
- GitHub e o sistema de ficheiros local: conservam codigo, configuracoes,
  instalacao e evidencias portaveis.
- SSH, GitHub Actions e outros transportes: entregam bytes e devolvem respostas;
  nao contem procedimentos do projeto, comandos de manutencao ou caminhos de fornecedores.

## Para cada tarefa com esta Skill

1. Identificar o alvo real e o tipo de analise solicitado.
2. Consultar tools/list e os dados de disponibilidade do REA quando necessario.
   Um nome publicado nao garante que o fornecedor esteja funcional no host.
3. Selecionar as operacoes MCP aplicaveis. Fazer uma auditoria multi-area se
   o pedido e profundo; nao confundir sintaxe JavaScript com backend Django,
   testes dinamicos ou cobertura integral.
4. Executar pelo REA as operacoes que o motor suporta. Se uma escrita de codigo
   requer GitHub, ou um teste exige o CI do projeto, usa-los como meios
   complementares e descreve-los como tal. Nao afirmar que REA executou
   tarefas feitas fora do motor.
5. Verificar as evidencias e os resultados INTERIORES das ferramentas, nao
   apenas o estado do GitHub Actions:
   * erro JSON-RPC ou result.isError => chamada falhou;
   * capture_process_scenario: normalized_result.exit.code diferente de 0
     => comando falhou mesmo que a captura MCP tenha status PASS;
   * avaliar settlement, cleanup e truncation_details; resultado parcial
     ou desconhecido nao deve ser chamado PASS integral.
6. Reportar o ID de execucao, chamadas MCP, fornecedor realmente utilizado,
   dependencias externas realmente utilizadas, resultados e lacunas.

## Cuidados de execucao, fora da ponte

- Comandos Bash gerados: testar sintaxe com bash -n antes de os executar.
- Git na aplicacao: executar com o utilizador proprietario do repositorio
  (stat -c %U), em vez de contornar avisos de dubious ownership.
- Deploy repetido: consultar SHA instalado e desejado. Se coincidirem,
  fazer apenas verificacao de saude, sem voltar a exigir o SHA antigo.
- Para resultados de fornecedor, usar Evidence e availability reportados pelo
  REA; nao equiparar 229 ferramentas anunciadas a 229 ferramentas certificadas.
- Preservar a versao original e nao escrever na arvore do autor.

## Criterio de portabilidade

O mesmo comando local rea-final-runtime/bin/rea-mcp deve responder a initialize
e tools/list sem GitHub Actions. A mudanca de cliente/ponte altera somente o
acesso ao comando, nao os fornecedores, dependencia, catalogo ou motor.
