# Codex autonomous execution — one-time GitHub authorization

## What is already installed

- The actual Codex CLI account login is on the existing Ubuntu VPS. Do **not** copy or create ChatGPT/Codex login tokens.
- The `martaxi-boss/VPS` GitHub Actions bridge already has SSH access through the existing `VPS_SSH_PASSWORD` secret.
- `[codex audit]` and `[codex fix project-leader]` remain legacy read-only/proposal flows. **Use `[codex run]` for implementation.**
- This pipeline is the reusable task/patch/CI/merge backbone. Telegram and additional agents later supply tasks or patches; they do not need their own GitHub write credentials.

## Exactly one credential still required from the Owner

Create a **fine-grained GitHub personal access token** owned by `martaxi-boss`, scoped only to **`martaxi-boss/VPS`** and **`martaxi-boss/Project-leader`**, with:

- `Contents: Read and write` — publish branches and guarded merges;
- `Pull requests: Read and write` — open and inspect PRs;
- `Actions: Read` — inspect the exact CI runs on candidate head;
- `Metadata: Read` (implicit for fine-grained tokens).

No administration, actions write, secrets access, packages write or account-wide/classic PAT scope is needed. Set an expiration/rotation policy. **Never paste the token into an Issue, chat, Telegram or repository file.**

Store it through **`martaxi-boss/VPS` -> Settings -> Secrets and variables -> Actions -> New repository secret**:

`CODEX_GITHUB_TOKEN`

The GitHub Actions runner checks that this secret exists **before starting the Codex CLI**, so an incomplete setup does not consume Codex quota. The token is only exposed to the trusted publication step, never transferred to the VPS Codex process.

For a larger set of repositories, a GitHub App installation token can replace this one-time fine-grained PAT later without changing the Codex sandbox/task protocol. Do not create or expose a generic token spanning unrelated repositories.

## Trigger from ChatGPT or later Telegram

Create one Owner-authored Issue in `martaxi-boss/VPS`:

**Title**: `[codex run] Fix the exact problem`

**Body**: first line is one of

`TARGET_REPOSITORY=martaxi-boss/Project-leader`

`TARGET_REPOSITORY=martaxi-boss/VPS`

Then describe the concrete authorized implementation goal and acceptance criteria. Tasks are source-controlled and issue-numbered. Only Owner-authored issues trigger this current route; Telegram bot-to-Owner authorization is a separate security binding to implement during the Telegram phase.

## What happens

1. Validate Issue owner, target allowlist and token presence; serialize tasks to protect quota.
2. Execute Codex inside disposable VPS clone with workspace-write sandbox, **without write credentials**; emit a guarded patch and any observed JSONL token counts.
3. An independent GitHub Actions runner checks exact source SHA, changed paths, patch size, symlinks and trust-sensitive paths. It publishes a short-lived branch and PR using the scoped token.
4. Wait for named target-repository CI workflows **on the exact candidate SHA**. Required failure, missing check, moving main, ambiguous PR state or GitHub rejection means **NO MERGE**, with a truthful Issue status and PR link.
5. For safe completed changes, integrate without bypassing protected branch rules. The Project Leader target requires an exact-SHA E2 transition authorization and independent Supervisor acceptance: this first bridge publishes a PR and stops rather than silently bypassing its control plane. VPS operational code also requires additional project-specific tests and stays as a PR; only ordinary VPS documentation changes can auto-merge initially. Post-merge hygiene runs from target repository's canonical workflows.

## Project Leader como controlador canónico de cada ordem Codex

O token GitHub permite publicar código, mas **não ativa por si só a Skill**.
Para todas as novas Issues de implementação `[codex run]`, o runner faz
obrigatoriamente um bootstrap de leitura **antes de consumir tokens Codex**:

1. Clona a `main` canónica de `martaxi-boss/Project-leader` para um local privado e separado (ou reutiliza o clone do alvo quando esse repositório é o próprio Project Leader).
2. Fixa uma única revisão Git SHA, verifica o manifesto, a Skill e o âmbito de autoridade, e injeta o conteúdo **exato** da Skill nesse pedido Codex. Nunca usa uma cópia de regras colada à mão.
3. Regista no resultado a revisão `RUNTIME_CANONICAL_REVISION` e a versão da Skill. Se não conseguir ler ou validar a versão, **não arranca o modelo nem publica correções**.
4. O Codex segue o ciclo de implementação, testes, higiene proporcional, recuperação e resultados verdadeiros, mas trabalha apenas num clone isolado do repositório-alvo. A publicação permanece entregue ao runner independente.

Este carregamento é a aplicação das regras canónicas ao **workflow de Codex**;
não é uma invocação automática do plugin instalado no ChatGPT, nem demonstra
que um Supervisor externo tenha sido lançado. O Supervisor é uma capacidade
interna de decisão para E1 e os controlos independentes de CI continuam
obrigatórios. Para efeitos materiais E2/E3, incluindo merges em `main`
do Project Leader, o circuito recusa a promoção sem autorização de transição
exata e prova independente de Supervisor. Não se pode inferir autorização de
produção nem das permissões do token GitHub.

## Boundaries and limitations

- This route handles normal **E1-compatible modifications**. Changes to `.github`, `.project-leader`, security credentials and Codex bridge control scripts are protected by a patch guard; E2/E3 governance or new authority requirements are real Human Gates unless separately authorized via the established Project Leader control plane.
- Repository-targeted checks and sandbox success are evidence, not a claim of universal functional correctness. Never silently deploy to production or permit uncontrolled service calls.
- For Codex `--json`, observed `turn.completed.usage` may expose input/cached/output token counts. **It does not expose the percentage of ChatGPT Business weekly quota.** Report `UNKNOWN` instead of inventing a percentage.
- The published GitHub Issues are visible to repository readers. Do not include passwords, screenshots containing personal data or proprietary task content.
- This document describes a configured pathway. It is **not proof of live write/merge operation** until a real Owner task has succeeded end to end after installing the secret.
