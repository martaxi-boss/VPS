# Codex: auditoria, dependencias e fases (sem chamadas a modelos)

O gestor recebe uma auditoria **real** do repositorio alvo numa revisao `main` de
40 caracteres, com `findings` por ficheiro e `work_items` com `depends_on`.
Nunca decide apenas pelas palavras da ordem. A skill Project Leader original
nao contem configuracoes de trabalhadores e nao pode ser alterada.

## Planear sem gastar quota Codex

```sh
python3 ops/codex_audit_strategy.py phases < auditoria.json
```

Este comando calcula, sem chamadas Codex, ate oito tarefas em fases de
um ou dois trabalhadores. Verifica antecipadamente todas as tarefas, incluindo
as adiadas; recusa caminhos fora da auditoria, ciclos, dependencias desconhecidas
e planos acima dos limites. Reutiliza o mesmo validador, limite de raciocinio
e guardas de escopo do executor VPS.

- Independentes, caminhos distintos e risco Low/Medium: ate dois em paralelo.
- Independentes com risco High: ate dois em serie, com PRs isoladas.
- Dependencia ou mesmos caminhos: fases distintas; sem suposicao de que uma
  alteracao em PR ainda nao integrada ja esta disponivel para a fase seguinte.
- Uma tarefa suficiente: apenas um trabalhador.

Apenas a primeira fase devolve `dispatch_audit` e o texto canonico
`dispatch_json`. O gestor deve enviar **exatamente** este ultimo texto como
corpo da Issue Owner `[agents run]`, sem reformatacao que possa exceder 6800
bytes. Antes de marcar a fase READY, o planeador percorre o mesmo
`agent_switch.parse_order` e `workflow_values` do executor GitHub Actions,
incluindo limites de 2200 caracteres por trabalhador e serializacao ASCII.
A revisao auditada deve continuar identica no momento do clone. Se o `main` mudou, o executor impede o gasto de tokens.
As fases seguintes tem `dispatch_audit: null`, estado
`HOLD_FOR_CI_AND_REAUDIT` e **nao** podem ser disparadas a partir de prova
antiga. O gestor primeiro valida a PR anterior, os testes, o estado do merge
ou NO_CHANGE e a nova auditoria; so depois gera o despacho seguinte.

O planeador nao invoca Codex, nao faz merges, nao altera codigo no projeto
alvo e nao supoe que o Codex Cloud esteja ligado a este chat.

## Limite operacional ainda por certificar

A funcao produz a sequencia segura de fases, mas **nao** implementa por si
um servico autonomo de reauditoria/CI entre fases nem valida automaticamente
uma situacao natural de quota esgotada. Os checks de CI testam o algoritmo
offline. A primeira execucao real do agendador de quota e uma sequencia
completa auditada com dependencia continuam a requerer evidencias separadas.
