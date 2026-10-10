# Codex Business - ponte ChatGPT/GitHub

Estado: **preparado, mas nao ativado**. Este ficheiro descreve a primeira integracao Codex do repositorio `martaxi-boss/VPS`.

## O que ja funciona nesta fase

- O ChatGPT ja pode criar GitHub Issues com a conta `martaxi-boss` (autoria verificada na issue #32, posteriormente fechada).
- O workflow `.github/workflows/codex-chatgpt-bridge.yml` aceita ordens do proprietario por Issue ou por execucao manual.
- O Codex usa um executor temporario do GitHub Actions e analisa os ficheiros do repositorio VPS, **nao** a maquina de producao.
- Auditorias nao alteram ficheiros. Correcoes sao propostas numa branch/PR; nao ha merge nem deploy automatico.
- Os resultados ficam no comentario da Issue e nos artefactos da execucao.

## O unico passo de autenticacao que falta

1. No ChatGPT Business, abre **Admin > Access tokens**. O administrador pode ter de ativar o direito a criar Codex access tokens e o acesso local ao Codex.
2. Cria um token com o scope **Codex**, nome `codex-vps-bridge` e uma validade curta (por exemplo, 30 dias).
3. No GitHub, abre **martaxi-boss/VPS > Settings > Secrets and variables > Actions > New repository secret**.
4. Cria o secret **`CODEX_ACCESS_TOKEN`** e coloca la o token. Nao coloques o token no codigo, na Issue ou no ChatGPT.
5. Rever e integrar a PR que contem este workflow. So depois passa a responder a novas Issues.

Documentacao oficial: https://developers.openai.com/docs/enterprise/access-tokens

Se o GitHub impedir a criacao automatica de pull requests, em **Settings > Actions > General** confirma a opcao para permitir GitHub Actions criar PRs. Se nao estiver disponivel, o workflow deixara uma branch para revisao.

## Como dar ordens pelo ChatGPT apos a ativacao

Pedido de auditoria:

> Cria uma Issue no repositorio martaxi-boss/VPS com titulo `[codex audit] Rever o repositorio VPS` e no corpo: `Verifica o codigo e indica problemas de seguranca, regressao e testes em falta. Nao alteres ficheiros.`

Pedido de correcao:

> Cria uma Issue no repositorio martaxi-boss/VPS com titulo `[codex fix] Corrigir problemas identificados` e descreve no corpo as correcoes exatas. Quero uma PR para aprovar, nunca um deploy.

Apenas Issues criadas pelo **proprietario do repositorio** e com os prefixos definidos desencadeiam Codex. As tarefas noutras Issues ou de outros utilizadores sao ignoradas.

## Limites e seguranca

- A quota e a disponibilidade de Codex continuam a depender do ChatGPT Business e das permissoes da conta.
- Se o token estiver ausente, expirado ou sem quota, a tarefa falha e fica registada no GitHub.
- O Codex nunca recebe a palavra-passe SSH do VPS neste workflow.
- Esta primeira fase trabalha **apenas neste repositorio**; mais repositorios e Cursor ficam para ligacoes independentes.
- Nao usar fork PRs ou codigo externo nao fiavel como fonte automatica de execucao privilegiada.
- Rever sempre o codigo proposto antes de integrar; nenhuma alteracao entra em producao automaticamente.
