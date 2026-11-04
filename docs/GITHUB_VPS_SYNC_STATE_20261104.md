# Sincronizacao GitHub ↔ VPS — 04/11/2026

> Estado factual e plano de conciliacao, nao certificado de deploy. Atualizar com respostas reais da VPS antes de marcar cada linha CONFORME.

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
- Comparacao GitHub `fadego` da release ativa para `main`: o diff final altera apenas `.gitignore` e adiciona `docs/VPS_INSTALLATION.md`. Nao ha alteracao do codigo da aplicacao nessa comparacao, apesar do historico divergente.
- Comparacao `iptvpn-bot`: diferencas em `ecosystem.config.js`, `start.sh`, `stop.sh`, scripts PM2 e unidade systemd; nao aplicar reset ou pull sobre os seis ficheiros tracked modificados.
- [#41879335553](https://github.com/martaxi-boss/VPS/actions/runs/41879335553): ponte Ferrari pelo caminho canonico testada com codigo de saida zero; nove servicos ativos. O executavel REA privado ainda e resolvido internamente pelo alias antigo, portanto preservar esse symlink por agora.
- [#41879408970](https://github.com/martaxi-boss/VPS/actions/runs/41879408970): instalador Ferrari rejeitou repeticao da release existente com `FERRARI_RELEASE_NOT_FRESH`, codigo 2. Nao e certificacao de deploy ou de falha funcional do motor.
- Foram preparados pedidos de fetch Git sem checkout/merge/reset, para `iptvpn-bot` e `pink-iptv` (commit `ce929323aba6...`) e separadamente para Low Cost com UID proprio (commit `1e68a3b3e860...`). Considerar executados apenas depois de existirem IDs Actions, resultados e read-back.

**Regra de fecho reforcada:** um `fetch` apenas atualiza referencias; nao e sincronizacao da release nem autoriza alteracoes locais. Nenhum dos checkouts com ficheiros alterados pode ser marcado como `main` implantada sem reconciliacao explicita.
