# Engenharia Reversa FINAL - norma de utilizacao independente de transportes

Esta norma acompanha a instalacao do REA no repositorio e numa workstation.
NAO pertence a GitHub Actions, SSH, Desktop Commander ou a outro transporte.
O motor original do autor permanece intacto. Nao criar outro MCP ou motor.

## Responsabilidades

- A IA externa (atualmente ChatGPT; Codex ou outro agente apenas depois de
  configurado) interpreta a ordem, consulta o catalogo MCP e coordena tarefas.
  O REA e o executor tecnico principal; a IA nao duplica ferramentas REA.
- REA original: executa as operacoes MCP e utiliza os fornecedores instalados
  quando suportados. Nao duplicar logica de analise ou seletores de fornecedores.
- GitHub e o sistema de ficheiros local: conservam codigo, configuracoes,
  instalacao e evidencias portaveis.
- SSH, GitHub Actions e outros transportes: entregam bytes e devolvem respostas;
  nao contem procedimentos do projeto, comandos de manutencao ou caminhos de fornecedores.

## Uma Skill e uma caixa de ferramentas REA-primeiro

- Engenharia Reversa FINAL e a entrada preferencial para trabalho tecnico
  quando a Skill estiver instalada e o cliente a reconhecer como relevante.
  A invocacao automatica nao e garantida em todos os chats e outros clientes
  de IA precisam de configurar a propria Skill e ligacao MCP.
- A inteligencia externa entende, raciocina, planeia e interpreta. O motor
  REA na instalacao Ubuntu executa todas as partes para as quais existe
  ferramenta MCP apropriada, instalada e operacional.
- A IA consulta as capacidades REA primeiro; nao cria substitutos diretos
  quando a capacidade ja existe e funciona. Escolhe operacoes por adequacao
  a tarefa, nunca por mera disponibilidade de um programa qualquer.
- Se o REA nao tem capacidade adequada, ou a integracao nao esta disponivel,
  comparar a lacuna real com as ferramentas da propria IA. A IA podera
  executar diretamente APENAS essa parte, identificando a excecao e a
  proveniencia do resultado. Retomar REA nas etapas seguintes suportadas.
- O REA executa os programas e seleciona fornecedores quando a operacao
  o permite; nao possui aqui outro agente de IA a interpretar pedidos livres.

## Para cada tarefa com esta Skill

1. Identificar o alvo real e o tipo de analise solicitado.
2. Consultar tools/list e os dados de disponibilidade do REA quando necessario.
   Um nome publicado nao garante que o fornecedor esteja funcional no host.
3. Selecionar as operacoes MCP aplicaveis. Fazer uma auditoria multi-area se
   o pedido e profundo; nao confundir sintaxe JavaScript com backend Django,
   testes dinamicos ou cobertura integral.
4. Executar pelo REA as operacoes que o motor suporta. Se faltar
   capacidade funcional para uma parte e forem precisos GitHub, CI ou
   ferramentas da IA, comparar primeiro e atribuir corretamente essa
   execucao externa, sem afirmar que foi realizada pelo REA.
5. Verificar as evidencias e os resultados INTERIORES das ferramentas, nao
   apenas o estado do GitHub Actions:
   * erro JSON-RPC ou result.isError => chamada falhou;
   * capture_process_scenario: normalized_result.exit.code diferente de 0
     => comando falhou mesmo que a captura MCP tenha status PASS;
   * avaliar settlement, cleanup e truncation_details; resultado parcial
     ou desconhecido nao deve ser chamado PASS integral.
6. Reportar o ID de execucao, chamadas MCP, fornecedor realmente utilizado,
   dependencias externas realmente utilizadas, resultados e lacunas.

## Crescimento incremental do motor e competencias

- Estudar novos candidatos reais em repositorios GitHub existentes, com
  comparacao entre ferramentas, fornecedores, licenca, compatibilidade Ubuntu,
  arquitetura, custos, versoes, dependencias e vias de integracao.
- Reutilizar Frida, Java, Ghidra, Hydra, JADX ou outras dependencias
  somente quando a instalacao e compatibilidade real estiverem confirmadas.
  Nao duplicar o mesmo fornecedor em cada projeto sem necessidade tecnica.
- Instalar uma dependencia nao basta: a competencia precisa de integracao
  funcional com o REA e teste real antes de ser declarada disponivel.
- Se for necessario evoluir o REA original, preparar upgrade incremental
  versionado e testado do motor pessoal, mantendo a versao operacional
  original preservada ate haver substituto validado. Nao alterar agora
  o motor do autor ou criar segundo MCP/coordenador.
- A configuracao das novas competencias pertence a instalacao do REA,
  nunca a ponte SSH/GitHub Actions nem a varias Skills concorrentes.

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
