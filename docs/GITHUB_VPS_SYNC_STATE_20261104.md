# Sincronizacao GitHub ↔ VPS — 04/11/2026

## Fecho definitivo Ferrari e alias — 04/11/2026, 19:06 UTC

**ESTADO MAIS RECENTE (prevalece sobre os registos cronológicos abaixo):** Ferrari ativo no Ubuntu da VPS em `/srv/projects/skill-universal/current` → `releases/292aeb7d10eecef8c3ca84760cd579e84e4b97f3`. `martaxi-boss/skill-universal` `main` tem o mesmo SHA. Tanto o workflow GitHub→SSH→Ferrari como o instalador completo manual estão fixados nesse SHA. Nenhum outro projeto foi alterado.

- [PR #61](https://github.com/martaxi-boss/skill-universal/pull/61) integrou um único script de manutenção com testes de migração estrita para Apktool e Valkey, remoção segura apenas do link histórico e rollback. As CI da branch e PR e a [CI pós-merge #41892571161](https://github.com/martaxi-boss/skill-universal/actions/runs/41892571161) passaram.
- [#41891510807](https://github.com/martaxi-boss/VPS/actions/runs/41891510807): último levantamento antes da migração, duas referências antigas em launchers e nove serviços ativos.
- [#41892664915](https://github.com/martaxi-boss/VPS/actions/runs/41892664915): 212 testes unitários no Ubuntu, auditoria de propriedade da pasta e launchers, nenhum processo externo identificado a usar a ligação, nove serviços ativos.
- [#41892883454](https://github.com/martaxi-boss/VPS/actions/runs/41892883454): **migração efetuada e certificada** dos launchers `tools/apktool-3.0.3/bin/apktool` e `tools/ferrari-services/valkey-server/bin/valkey-server`, ambos agora com caminhos absolutos dentro de `skill-universal`. **Symlink `/home/ubuntu/.local/share/motor-ferrari` eliminado**. Ferrari Doctor e chamada REA reais PASS, nove serviços ativos.
- [#41893144445](https://github.com/martaxi-boss/VPS/actions/runs/41893144445): script certificado transferido de staging privado para uma nova release imutável e pasta `.staging` vazia removida.
- [#41893374822](https://github.com/martaxi-boss/VPS/actions/runs/41893374822): `current` comutado atomicamente para `292aeb7d...`, com verificação dos dois launchers, Ferrari Doctor, REA MCP, alias ausente e 9/9 serviços ativos. A versão `70458fc1...` e a antiga `0a1a4c1...` continuam preservadas **dentro** do projeto, sem instalações duplicadas noutros diretórios.
- [#41893641043](https://github.com/martaxi-boss/VPS/actions/runs/41893641043): **certificação final independente**, já com o GitHub Actions selecionando o novo SHA. `tools/list` real do REA 6.8.0 devolveu **229 ferramentas**; auditoria da release identificou **0 launchers por migrar, 0 processos externos com referência ao alias, symlink ausente, fallback preservado e 9/9 serviços ativos**.
- O workflow `.github/workflows/ferrari-independent-vps-delivery.yml` permanece **manual-only**; não executar uma reinstalação da release existente apenas para certificar esta manutenção. A ponte `ferrari-skill-request.yml` permanece automática apenas para pedidos novos.

**Conclusão Ferrari:** GitHub e VPS alinhados, launchers privados migrados, atalho eliminado, sem reinícios de serviços nem alterações a outros projetos. A listagem de 229 ferramentas comprova a ponte e o catálogo, não 229 certificações individuais. Os restantes projetos ainda têm as divergências de runtime indicadas na auditoria histórica abaixo; **não declarar sincronização completa da VPS inteira**.

---

> Histórico das fases de auditoria e sincronização. Para o estado atual do Ferrari, consultar o **Fecho definitivo** acima.

## Regra de instalacao
- Raiz unica: `/srv/projects/<nome-exato-do-repositorio>`.
- Nao partilhar dependencias privadas, runtimes, fornecedores, sessoes ou bases de dados entre projetos.
- Nao sobrescrever codigo local, alteracoes nao committed, releases ativas nem dados privados por `git pull --force`.
- Cada projeto requer leitura de `HEAD`, estado do checkout, origem remota, SHA do GitHub, eventual divergencia, backup recuperavel, rollout individual e read-back.
- Integracoes obrigatorias do Ubuntu (systemd, Nginx, PostgreSQL) ficam inventariadas como infraestrutura de sistema.

## Ultima comprovacao fisica na VPS
- [Actions #41874024612](https://github.com/martaxi-boss/VPS/actions/runs/41874024612): oito pastas fisicas com nomes exatos; cerca de 48,58 GB livres; nove servicos essenciais ativos; sem raizes simbolicas cruzadas.
- [Actions #41875423498](https://github.com/martaxi-boss/VPS/actions/runs/41875423498): residuos externos antigos ausentes; alias de transporte Ferrari presente e apontado para a raiz canonica.
- Esta evidencia **nao** demonstra que os oito checkouts locais coincidam com as branches `main`.

## GitHub main observado em 04/11/2026

| Projeto | SHA main | Estado VPS |
|---|---|---|
| `VPS` | `6d99327bc44d7c7b8ef55956043e629b0cd055c9` | Confirmar HEAD/ficheiros locais (infraestrutura) |
| `skill-universal` | `8a839fa7d7ba866b541153b5e9bd8a8a29637786` | Release Ferrari operacional fixada em `0a1a4c1...`; nao atualizar motor sem testes |
| `fadego` | `7e26e96e43647e0a4f7e40c75f9087f40961ac80` | Release anteriormente ativa `2b3554e...`; historico divergente, nao forcar |
| `Codex` | `31b0b0e6f8611f6789ec101e5d581de5ccbac3cc` | Confirmar instalacao local |
| `pink-iptv` | `58abe37677482b7fc4d1c877a5cbc6b5c6b46de7` | Confirmar alteracoes locais e backend/VPN antes de sincronizar |
| `lowcost-europa` | `58340ef2608cbdb927a0e97bf717b0f5321c5e09` | Confirmar release e dados; testar backup/restauro |
| `telegram-robot-leads` | `99c106022ef9e0691c05d74278dce8fd9791b8e8` | Preservar sessoes e processos PM2 privados; confirmar HEAD |
| `iptvpn-bot` | `de152539a839c544a4eb802197c7114c823efc96` | Historico divergente; preservar codigo operacional e sessoes |

## Mudancas reais desta fase no GitHub
- `.github/workflows/ferrari-skill-request.yml`: transporte de pedidos/execucao/ZIP usa `/srv/projects/skill-universal`, sem alteracao da credencial SSH, host pin ou motor fixado.
- `.github/workflows/ferrari-independent-vps-delivery.yml`: raiz de releases e scripts usam `/srv/projects/skill-universal`.
- `.github/workflows/vps-project-size-inventory-20261103.yml`: inventario aponta para a raiz oficial, e nao para o alias em HOME.
- `skill-universal/BOOTSTRAP.md` e `skill/motor-universal-linux/references/github-bridge.md`: referencias de executaveis privados documentadas na raiz oficial.
- Alias `/home/ubuntu/.local/share/motor-ferrari`: **nao removido**; requer teste real da ponte nova e ausencia de consumidores locais.

## Execucoes abertas para validar
- [#41878914110](https://github.com/martaxi-boss/VPS/actions/runs/41878914110): auditoria read-only por projeto (HEAD, origin, changes, services).
- [#41879335553](https://github.com/martaxi-boss/VPS/actions/runs/41879335553): smoke real pelo caminho canonico.
- [#41879408970](https://github.com/martaxi-boss/VPS/actions/runs/41879408970): instalacao completa Ferrari automatica por alteracao de workflow; nao classificar como teste simples.
- [#41879706072](https://github.com/martaxi-boss/VPS/actions/runs/41879706072): inventario VPS read-only pelo caminho canonico.

## Criterios de fecho
1. Confirmar resultados/artefactos Actions e recolher SHA/estado local dos oito projetos, sem segredos.
2. Se houver divergencia: preservar HEAD/release, diffs e dados, nunca reset/force; decidir reconciliação individual.
3. Testar pontes, arranques, backups e health dos serviços apos cada mudanca.
4. Remover aliases apenas depois de provar zero consumidores e caminho definitivo em producao.
5. Repetir auditoria real com SHA, espaco e nove servicos ativos; so entao marcar sincronizacao completa.

**Estado atual:** caminhos GitHub do Ferrari alinhados; sincronizacao dos checkouts VPS e retirada de aliases ainda nao certificadas.


## Leitura real de checkouts e releases apos os dois preflights
- [#41878914110](https://github.com/martaxi-boss/VPS/actions/runs/41878914110): nove servicos ativos. `iptvpn-bot` tem branch `security/iptvpn-bot-secret-vault-001`, HEAD `6d26ea34a584...` e seis ficheiros tracked modificados; `pink-iptv` usa `builder/android-shell-002`, HEAD `ccccaf1eb25c...`, seis ficheiros tracked modificados e 16 nao rastreados. `lowcost-europa` apresentava validacao Git afetada por ownership no primeiro teste.
- [#41880863118](https://github.com/martaxi-boss/VPS/actions/runs/41880863118): a verificacao Git com `safe.directory` explicito confirmou Low Cost com HEAD `388860c6a167...` detached, um ficheiro tracked modificado e origin acessivel; `iptvpn-bot` e PINK tambem alcancam os SHAs atuais remotos sem alterar os checkouts. Nenhuma destas tres pastas tem ainda o commit `main` mais recente no seu object store local. FADEGO e Ferrari usam releases, nao Git diretamente na raiz; o `current` FADEGO contem checkout `2b3554ec...`.
- **Correcao de auditoria FADEGO:** a comparacao GitHub de commits reportava apenas tres commits no ramo `main` e duas mudancas relativas ao merge-base, mas NAO demonstra equivalencia entre as arvores finais quando os historicos divergem. A comparacao direta dos blobs de todas as arvores (release ativa `2b3554ec...` contra `main` `7e26e96e...`) encontrou **168 caminhos diferentes**, incluindo codigo funcional de reservas, autenticacao, admin e configuracao. NAO aplicar deploy ou eliminacao sem conciliacao de funcionalidades e testes.
- Comparacao `iptvpn-bot`: diferencas em `ecosystem.config.js`, `start.sh`, `stop.sh`, scripts PM2 e unidade systemd; nao aplicar reset ou pull sobre os seis ficheiros tracked modificados.
- [#41879335553](https://github.com/martaxi-boss/VPS/actions/runs/41879335553): ponte Ferrari pelo caminho canonico testada com codigo de saida zero; nove servicos ativos. O executavel REA privado ainda e resolvido internamente pelo alias antigo, portanto preservar esse symlink por agora.
- [#41879408970](https://github.com/martaxi-boss/VPS/actions/runs/41879408970): instalador Ferrari rejeitou repeticao da release existente com `FERRARI_RELEASE_NOT_FRESH`, codigo 2. Nao e certificacao de deploy ou de falha funcional do motor.
- Foram preparados pedidos de fetch Git sem checkout/merge/reset, para `iptvpn-bot` e `pink-iptv` (commit `ce929323aba6...`) e separadamente para Low Cost com UID proprio (commit `1e68a3b3e860...`). Considerar executados apenas depois de existirem IDs Actions, resultados e read-back.

**Regra de fecho reforcada:** um `fetch` apenas atualiza referencias; nao e sincronizacao da release nem autoriza alteracoes locais. Nenhum dos checkouts com ficheiros alterados pode ser marcado como `main` implantada sem reconciliacao explicita.


## Resultado das sincronizacoes Git e reconciliacao controlada FADEGO
- [#41881691025](https://github.com/martaxi-boss/VPS/actions/runs/41881691025) **PASS**: `git fetch --no-tags origin main` em `iptvpn-bot` e `pink-iptv`. Novas refs locais `de152539...` e `58abe376...`. HEAD, hashes dos ficheiros tracked modificados, lista untracked e nove servicos preservados. Isto nao fez checkout nem deploy.
- [#41882096256](https://github.com/martaxi-boss/VPS/actions/runs/41882096256) **PASS**: `git fetch` de `lowcost-europa` com UID proprio 999; ref `58340ef...`, HEAD detached `388860c6...`, alteracao tracked e servicos preservados. Sem deploy.
- [#41882316687](https://github.com/martaxi-boss/VPS/actions/runs/41882316687) **PASS**: comparacao de blobs dos ficheiros tracked modificados contra o `origin/main` efetivamente atualizado. Em `iptvpn-bot`, `ecosystem.config.js`, `start.sh` e `stop.sh` ja igualam o blob de main, duas remocoes locais tambem estao removidas em main, mas `.gitignore` e `main.py` divergem. Em `pink-iptv`, seis ficheiros backend tracked modificados ja igualam os blobs de `main`; os outros caminhos da release e 16 ficheiros nao rastreados nao estao certificados equivalentes.
- **FADEGO:** a release instalada `2b3554ec...` corresponde ao HEAD original da [PR #15](https://github.com/martaxi-boss/fadego/pull/15), branch `integration/20261016-fadego-candidate`. Foi criado um merge normal (sem force) na MESMA branch, commit `f577a8e20301c76fd4852c94f46460df6aa41562`, com pais `2b3554ec...` e `7e26e96e...`. A arvore da aplicacao instalada foi preservada integralmente; so mudou o blob `.gitignore` para a versao main e foi acrescentado `docs/VPS_INSTALLATION.md`. O main permaneceu `7e26e96e...`. A comparacao `main...branch` ficou ahead 113, behind 0; 166 ficheiros de diferenca funcional mantidos na PR aberta. Sem merge no main, sem deploy na VPS.
- **Verificacao CI da PR #15:** o commit novo nao apresenta checks/reportes no GitHub no momento da leitura; CI nao esta certificada e a PR nao deve ser integrada automaticamente.
- **Ferrari:** embora a ponte por caminho canonico tenha passado, a release ativa guarda referencias internas ao alias anterior (`engine/rea_mcp.py`, `engine/ferrari.py`, `engine/tool_runtime.py`, `engine/runtime_discovery.py`, instaladores). Nao apagar o alias. A execucao automatica completa #41879408970 falhou por release ja existente; nao interpretar essa falha como indisponibilidade do Ferrari.

**Estado de encerramento:** reconciliacao de historico da branch FADEGO concluida SEM mudar aplicacao instalada; fetch refs Git de tres projetos concluido; restam conciliacao dos ficheiros operacionais por projeto, testes de releases, migracao interna Ferrari e prova de ausencia de consumidores de aliases.

## Ferrari — levantamento final de consumidores na VPS
- [#41887166727](https://github.com/martaxi-boss/VPS/actions/runs/41887166727) **PASS**, read-only com REA MCP e ZIP: raiz física `/srv/projects/skill-universal`, `current` ancora em `releases/0a1a4c190a7d33752d6dc3f4418ed44735c8a7dd`, alias de HOME é symlink para a raiz correta. **41 scripts/launchers examinados**, **47 ocorrências textuais** de `motor-ferrari` (incluem comentários, nomes de motor e referências operacionais; não são 47 consumidores ativos). Os launchers instalados de **Apktool** e **Valkey** contêm referências antigas. Nove serviços ativos, ~48,58 GB livres.
- Ferramentas e instaladores novos na `main` do repositório Ferrari `skill-universal`: [PR #58](https://github.com/martaxi-boss/skill-universal/pull/58) e [PR #59](https://github.com/martaxi-boss/skill-universal/pull/59) integradas; `main=15d52a09421d70f8b5377bcde1280455ae5c971f`, [CI pós-merge #41887024924](https://github.com/martaxi-boss/skill-universal/actions/runs/41887024924) PASS. **Estas alterações não modificaram a release ativa**.
- [PR #60](https://github.com/martaxi-boss/skill-universal/pull/60): correção idempotente do instalador para converter com rollback o launcher do Apktool já instalado. Aguardar CI e testes reais antes de ativar; não confundir com remoção concluída de alias.
- Não mudar `current` nem eliminar o symlink histórico sem: release nova isolada testada, rotas e operações REA/Apktool, inspeção dos launchers instalados, arranque/recovery e invariância dos demais serviços.


## Ferrari — release ativa, ponte nova e launchers pendentes

- [#41888432384](https://github.com/martaxi-boss/VPS/actions/runs/41888432384) PASS: GitHub Ferrari `70458fc1b44102b440d2d4c335b5e54f5279f25c` clonado para staging privado, **208/208 testes reais no Ubuntu**, scripts válidos, doctor e REA privado PASS.
- [#41888861592](https://github.com/martaxi-boss/VPS/actions/runs/41888861592) PASS: candidata executou `engine.skill_job` e `tools/list` real do REA 6.8.0 no caminho privado canónico; release antiga e nove serviços preservados.
- [#41889625183](https://github.com/martaxi-boss/VPS/actions/runs/41889625183) PASS: candidata movida para `releases/70458fc1...` sem mudar `current`.
- [#41889881644](https://github.com/martaxi-boss/VPS/actions/runs/41889881644) PASS: `current` comutado atomicamente para release `70458fc1...`; doctor e MCP reais passaram; nove serviços intactos; release antiga `0a1a4c1...` preservada como fallback.
- [#41890135962](https://github.com/martaxi-boss/VPS/actions/runs/41890135962) PASS: workflow de pedido GitHub passa a usar o commit ativo `70458fc1...` no selector e na VPS; `tools/list` devolveu **229 ferramentas**, erro MCP ausente. Catálogo disponível não significa 229 ferramentas certificadas funcionalmente.
- O workflow de instalação completa `ferrari-independent-vps-delivery.yml` ficou **manual-only** para evitar reinstalações disparadas por alterações ao workflow.
- [#41890497316](https://github.com/martaxi-boss/VPS/actions/runs/41890497316) PASS read-only: os launchers privados `tools/apktool-3.0.3/bin/apktool` e `tools/ferrari-services/valkey-server/bin/valkey-server` ainda têm UMA referência literal ao antigo `$HOME/.local/share/motor-ferrari` cada. O teste intencional como root falhou por resolver `/root/.local/...`; isso **não demonstra falha para o utilizador `ubuntu`**, mas prova que não são independentes do alias. Não apagar alias até migrar ambos e validar as versões como proprietário.
- A tentativa de mutação do launcher Apktool não foi aceite pelo controlo da ferramenta e **não foi executada**. Não marcar launchers nem higienização final como concluídos.

**Estado factual:** Ferrari ativo, REA e ponte atual sincronizados. O fallback antigo e alias temporário ficam preservados até migração dos launchers, testes reais e prova de ausência de consumidores.
