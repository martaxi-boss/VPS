# Metodo simples: o chat orienta, o REA executa

## Para qualquer pedido tecnico

1. A IA do chat interpreta o pedido em linguagem natural, planeia e escolhe as chamadas MCP. A Skill e a unica entrada, quando disponivel. O REA e a primeira via para executar, ler, editar, construir, testar e verificar.
2. Consultar os contratos MCP reais do REA (`tools/list`) e capacidades disponiveis; nao tratar a listagem como certificacao. Reutilizar a informacao obtida ao longo da tarefa sem consultas repetidas desnecessarias.
3. Para cada etapa, comparar o contrato MCP com o alvo e a disponibilidade real do fornecedor. Usar ferramentas especializadas apenas se aceitarem esse tipo de alvo e tiverem os pre-requisitos. Para Django/Python/Git, `capture_process_scenario` permite ao proprio REA ler, alterar e testar pelo Linux; nao e fallback da IA, nem deve ser confundido com analise especializada. A IA prepara o trabalho, mas faz o REA executar e verificar.
4. Se houver erro, diagnosticar argumentos, ambiente, permissao, ferramenta ou timeout; corrigir a operacao REA e voltar a testar so a parte afetada. Para Git, usar a conta proprietaria e modo nao interativo (`GIT_PAGER=cat`, `PAGER=cat`, `git --no-pager` quando adequado), sem configuracao global. Para alterar codigo, executar patch minimo pelo REA e confirmar diff, testes e resultado.
5. Apenas quando o REA nao tiver meio funcional para a parte do pedido, usar ferramenta da IA ou servico conectado para essa parte concreta. Identificar a excecao; continuar no REA quando voltar a ser possivel.
6. Separar tres resultados: transporte GitHub Actions/SSH, resposta MCP e cada verificacao interna. Em `normalized_result.exit`, codigo nao zero, sinal ou `idle_timeout`/timeout sao FALHA, mesmo com transporte verde; codigo nulo sem sucesso comprovado nao e PASS. Codigo zero ainda requer subtestes confirmados. Inspecionar `frames`, `settlement`, `cleanup` e `truncation_details.raw_terminal`; distinguir observacao parcial de erro de execucao. Para `set +e`, `|| true`, `curl -k` ou saida parcial, nao certificar verificacao afetada sem prova independente.
7. Comunicar ao utilizador o resultado normalmente, com evidencias, IDs, proveniencia de cada parte, limites e lacunas, sem atribuir ao REA trabalhos executados pelo GitHub ou pelo ChatGPT.

## Ao crescer a caixa de ferramentas

- Estudar ferramentas e projetos reais do GitHub, confirmar licenca e compatibilidade Ubuntu e reutilizar as dependencias REA existentes quando compativeis.
- Uma instalacao nao equivale a capacidade MCP. Integrar, testar e somente depois considerar disponivel; atualizar o motor de forma incremental quando o utilizador decidir evoluir essa instalacao.
- Nao criar outra Skill, motor, MCP ou coordenador; nao colocar codigo, regras, fornecedores ou seletores na ponte GitHub Actions/SSH.
- Ativacao automatica depende do cliente de chat e nao pode ser garantida em todas as conversas nem em Codex sem configuracao.
