# Metodo simples: o chat orienta, o REA executa

## Para qualquer pedido tecnico

1. A IA do chat interpreta o pedido em linguagem natural, planeia e escolhe as chamadas MCP. A Skill e a unica entrada, quando disponivel. O REA e a primeira via para executar, ler, editar, construir, testar e verificar.
2. Consultar os contratos MCP reais do REA (`tools/list`) e capacidades disponiveis; nao tratar a listagem como certificacao. Reutilizar a informacao obtida ao longo da tarefa sem consultas repetidas desnecessarias.
3. Para cada etapa, selecionar a ferramenta mais adequada do catalogo. Preferir ferramentas especializadas quando existem; usar `capture_process_scenario` para executar processos Linux que nao exigem uma ferramenta mais especifica. O motor usa os fornecedores instalados quando a operacao o suporta.
4. Se houver erro, diagnosticar se foi argumento, ambiente, permissao ou capacidade ausente. Corrigir o uso do REA quando possivel antes de mudar de executor. Para Git de projetos, usar a conta proprietaria apropriada, sem adicionar excecoes globais por conveniencia.
5. Apenas quando o REA nao tiver meio funcional para a parte do pedido, usar ferramenta da IA ou servico conectado para essa parte concreta. Identificar a excecao; continuar no REA quando voltar a ser possivel.
6. Separar tres resultados: transporte GitHub Actions/SSH, resposta MCP e verificacao interna. O exit zero de um shell nao prova que subcomandos passaram; inspecionar linhas de erro, codigos, verificacoes e `normalized_result`. Se ha `set +e`, `|| true`, `curl -k` ou saida parcial, exigir interpretacao especifica da verificacao afetada.
7. Comunicar ao utilizador o resultado normalmente, com evidencias, IDs, proveniencia de cada parte, limites e lacunas, sem atribuir ao REA trabalhos executados pelo GitHub ou pelo ChatGPT.

## Ao crescer a caixa de ferramentas

- Estudar ferramentas e projetos reais do GitHub, confirmar licenca e compatibilidade Ubuntu e reutilizar as dependencias REA existentes quando compativeis.
- Uma instalacao nao equivale a capacidade MCP. Integrar, testar e somente depois considerar disponivel; atualizar o motor de forma incremental quando o utilizador decidir evoluir essa instalacao.
- Nao criar outra Skill, motor, MCP ou coordenador; nao colocar codigo, regras, fornecedores ou seletores na ponte GitHub Actions/SSH.
- Ativacao automatica depende do cliente de chat e nao pode ser garantida em todas as conversas nem em Codex sem configuracao.
