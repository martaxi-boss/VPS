# VPS

Private operations repository for controlled VPS maintenance.

Para executar o Codex autonomamente, consulte as [instruções](ops/CODEX-AUTONOMOUS-SETUP.md).

## Certificação REA em curso (ramo `rea/one-skill-bridge-20261023`)

Para retomar a certificação do motor REA após mudar de conversa (incluindo ChatGPT Windows), consultar primeiro [o registo canónico e o método estável de recuperação de GitHub Actions `push`](rea-linux/certification/README.md#recuperação-canónica-de-github-actions-após-mudar-de-conversa-push) e [o ledger funcional](rea-linux/certification/functional-ledger.json). O wrapper `fetch_commit_workflow_runs` não é uma fonte válida para os runs `push` deste workflow; usar `mcp__GitHub__fetch` na REST API descrita na documentação, sem criar novos motores, pontes ou plugins. As instruções deste ramo não alteram os outros projetos.

## Regra operacional: um projeto por ordem, infraestrutura existente

**"Trabalha apenas no projeto X" limita o âmbito da operação; não é uma
autorização nem uma necessidade para criar uma nova ligação à VPS.**

Em ordens transmitidas ao REA/ChatGPT para projetos alojados na VPS:

1. Fixar um único repositório/projeto alvo, os caminhos, processos e ficheiros
   permitidos. Não alterar os outros projetos, os seus segredos, serviços,
   bases de dados, workflows ou processos PM2.
2. **Reutilizar primeiro o caminho operacional já existente e comprovado**:
   GitHub Actions do repositório VPS, autenticação SSH já provisionada,
   identidade SSH fixada e comandos limitados ao projeto autorizado.
   Um Secret do repositório VPS **não aparece automaticamente** nos Actions
   de outro repositório. A ausência dessa credencial num workflow novo
   não significa que a ligação anterior deixou de funcionar.
   A utilização do repositório `VPS` como **executor central** não autoriza
   alterações nos restantes projetos: código, diretórios, processos e serviços
   continuam limitados ao projeto indicado. Alterar o próprio executor
   partilhado exige âmbito e autoridade específicos; executar um workflow
   central já existente não é o mesmo que alterar a sua configuração.
3. Uma ordem de isolamento **nunca justifica por si só** criar workflows,
   chaves SSH, Secrets, OAuth, novas pontes, motores, Skills, Plugins,
   servidores ou coordenadores. Não copiar, revelar ou transferir credenciais
   entre repositórios. Não substituir uma autenticação existente sem motivo
   técnico e validação.
4. Os workflows específicos que já existam podem continuar para CI, builds
   ou deploys que efetivamente precisem deles; **não** criar um novo workflow
   por cada projeto, fase ou ordem. Antes de propor um novo, demonstrar
   por que razão nenhum caminho existente satisfaz a operação, delimitar
   os seus efeitos e obter autorização explícita para essa mudança de
   infraestrutura. Isto não impede a execução das tarefas normais.
5. Se uma instalação for bloqueada por um Secret em falta, falhar antes
   do SSH, preservar o estado existente e verificar o percurso central;
   não pedir repetidamente ao proprietário para reintroduzir passwords,
   nem afirmar que a VPS perdeu acesso sem uma prova de conectividade.
6. Reutilizar credenciais **não** alarga permissões: validar a identidade do
   servidor, a autoridade para o projeto, os caminhos e a ação concreta
   antes de executar. O transporte MCP do REA não é um executor genérico
   de deploy de outros projetos. Registar resultados reais (commit, run ID,
   operação e âmbito) sem revelar segredos.

Esta regra pertence à camada de coordenação/operação. O código original
REA 6.8.0, o catálogo MCP e as dependências do autor permanecem inalterados.
Esta preferência por GitHub Actions → SSH → VPS aplica-se às operações de
instalação, atualização e administração que necessitem de acesso à VPS.
**Não substitui o acesso normal às ferramentas MCP do REA**, incluindo a
ligação autenticada por OAuth já existente. Não muda as permissões de
qualquer agente nem transfere Secrets para outros repositórios.

A regra deve ser lida pelo agente que planeia e altera workflows; não é uma
alteração à autenticação do servidor REA nem ativa acesso SSH por si só.
