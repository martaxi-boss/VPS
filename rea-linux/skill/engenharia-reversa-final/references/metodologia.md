# Metodo simples da caixa de ferramentas REA FINAL

## Cada tarefa

1. A IA externa compreende a ordem. Se esta Skill estiver instalada e for relevante, aplica-la sem exigir `@REA`.
2. Consultar as operacoes MCP reais (`tools/list`) e disponibilidade; nunca deduzir capacidade a partir de nomes ou de dependencias apenas instaladas.
3. REA e sempre o executor preferencial para partes tecnicas que suporta. A IA coordena e interpreta. O REA gere os seus fornecedores quando a operacao o permite.
4. Se faltar uma ferramenta ou integracao apropriada, comparar a capacidade REA existente com a ferramenta propria disponivel na IA. Usar o recurso externo somente para a parte nao executavel pelo motor e declarar a proveniencia.
5. Para novas competencias: localizar projetos reais no GitHub, estudar compatibilidade Ubuntu, verificar licenca, dependencias e reutilizacao do runtime, testar a integracao e apenas depois registar como operacional.
6. Separar estado do transporte, resultado MCP e resultado interno da ferramenta. Em capturas, ler `structuredContent.normalized_result.exit.code`, `settlement`, `cleanup` e cobertura.
7. Devolver resultados, lacunas, IDs de execucao e comprovativos; nunca atribuir ao motor trabalho que foi feito por CI, GitHub ou ferramentas nativas do ChatGPT.

## Fronteiras fixas

- Skill: entrada e instrucoes reutilizaveis, nao um segundo executor.
- REA: o unico motor principal da caixa, com fornecedores e dependencias no seu ambiente Ubuntu.
- GitHub Actions/SSH atual: simples transporte MCP, nao centro de decisao.
- Outros clientes de IA: necessitam da propria configuracao de Skill e MCP; nao pressupor ativacao automatica universal.
- Evolucao futura: estudar upgrades versionados preservando a instalacao que ja funciona; nao alterar o REA original nesta fase.
