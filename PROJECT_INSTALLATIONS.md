# Instalacoes da VPS por repositorio GitHub

**Auditoria factual:** 2026-11-03 19:11 UTC, Ubuntu VPS. **Evidencia:** https://github.com/martaxi-boss/VPS/actions/runs/41700745454.

> Este ficheiro e um mapa de instalacoes, nao uma declaracao de que todas as migracoes ja ocorreram. Nunca copiar valores de credenciais ou sessoes para o GitHub.

## Regra do proprietario para novas instalacoes

- O nome da pasta principal da instalacao deve corresponder **exatamente** ao nome do repositorio GitHub (maiusculas/minusculas, hifens e tudo).
- Para novas instalacoes, o local canonico proposto e `/srv/projects/<nome-exato-do-repositorio>/`. As instalacoes antigas nao devem ser movidas sem auditar e ajustar servicos, permissões e referencias.
- Dentro do projeto devem ficar o seu codigo, dependencias exclusivas (por exemplo `.venv`, `node_modules`), configuracoes privadas e dados operacionais, logs, ficheiros temporarios, testes e artefactos, em subpastas identificadas e com permissoes proprias.
- Codigo, manifesto de dependencias e templates de configuracao ficam **versionados no GitHub**. Segredos, sessoes, bases de dados, logs, venvs e artefactos gerados **nao devem ser publicados no GitHub**; precisam de backup ou exportacao proprio.
- Excecoes tecnicas do Ubuntu: bibliotecas/apt globais, systemd em `/etc/systemd/system`, configuracoes Nginx, PM2 global, PostgreSQL, WireGuard e outros servicos partilhados. Devem ser documentados no projeto e removidos com o procedimento de desinstalacao, nao duplicados para cada projeto.
- Nenhum projeto deve ser considerado desinstalavel apenas com `rm -rf` ate possuir procedimento testado que pare processos, timers e servicos, trate dados e segredos, e remova somente as suas proprias referencias.
- Cada instalacao nova ou migrada requer **read-back**: caminho canonico, release/revision SHA, servico/processo ativo e validacao do funcionamento.

## Mapa real de instalacoes identificadas (nao normalizadas)

| Repositorio GitHub | Pasta principal atual | Componentes fora da pasta | Estado de alinhamento |
| --- | --- | --- | --- |
| `telegram-robot-leads` | `/srv/projects/telegram-robot-leads` | `/opt/telegram-robot-leads` (symlink temporario), `/var/lib/telegram-robot-leads`, `/root/project-secrets/telegram-robot-leads`, PM2 global | Raiz e scripts migrados fisicamente; dados, duas sessoes e processo PM2 ainda por migrar. |
| `iptvpn-bot` | `/srv/projects/iptvpn-bot` | `/root/iptvpn_bot` (ligacao temporaria), `/etc/iptvpn-bot`, `/root/project-secrets/iptvpn_bot`, PM2 global | Nome canonico atingido fisicamente; arranque PM2 e dados privados ainda externos. |
| `pink-iptv` | `/srv/projects/pink-iptv` | `/srv/pink-iptv` (ligacao temporaria), configuracao VPN e unidades do Ubuntu; provas em `/srv/projects/pink-iptv/tests/device-proof/` | Nome canonico atingido fisicamente; backend ativo, 6 alteracoes locais preservadas. |
| `fadego` | `/srv/fadego-staging` | `/var/www/fadego-preview`, unidade systemd e servicos partilhados | Nome diferente; versoes em `releases/`, `current` aponta para uma release ativa. |
| `lowcost-europa` | `/srv/projects/lowcost-europa` | `/srv/lowcost-europa` (ligacao temporaria), `/var/lib/lowcost-europa`, `/var/www/lowcost-europa`, segredos e timers | Instalacao fisica no nome canonico; servico e backups ainda usam caminho antigo. |
| `skill-universal` (Ferrari) | `/home/ubuntu/.local/share/motor-ferrari` | Programas e pacotes Ubuntu partilhados | Nome diferente; runtime instalado nao comprovado como clone direto do repo. |
| `Engenheira-reversa` | `/home/ubuntu/.local/share/rea-chatgpt-trial` (clone em `repository/`) | `/home/ubuntu/rea-final-runtime`, `rea-original-upstream-680`, `rea-original-upstream-680-evidence`, `/var/lib/rea-reversa` | Instalacoes diferentes, incluindo o upstream `morluto/rea`. Nao unir sem comprovar a propriedade e independencia de cada runtime. |
| `Project-leader-codex` | Clone do repo nao confirmado na VPS | `/home/ubuntu/codex-agent`, `codex-bridge`, `.codex` | Componentes de Codex identificados; a relacao com o projeto precisa de verificacao. Nao criar coordenador na VPS; supervisor e passivo. |
| `VPS` | Repositorio no GitHub e execucoes temporarias Actions/SSH | Ficheiros do sistema, unidades systemd e observacao Telegram | Infraestrutura partilhada; Supervisor Telegram sem servico residente independente confirmado. |

**Outros repositorios da conta GitHub sem implantacao VPS diretamente identificada no inventario:** `Project-leader`, `sms-man`, `insolvencia`, `free-numbers`, `MotionCam-iOS`, `IOS-16-USB-4k`, `IOS-15-USB`, `VCAM-PRO`, `Orquestra-de-agentes`, `Codex`, `Criativos-anuncios`, `Qwen`, `dopamine`. Ausencia de identificacao nao prova ausencia de todos os ficheiros.

## Desfasamento de revisoes (dados verificados nesta auditoria)

| Repo | GitHub `main` | Checkout/release identificada na VPS |
| --- | --- | --- |
| `iptvpn-bot` | `b0797b27e8f7` | `6d26ea34a584` (checkout limpo) |
| `telegram-robot-leads` | `8cf516b7377f` | `7c0ef8a1d9be` (snapshot Git interno; o runtime tambem recebeu ajustes Opt-in) |
| `pink-iptv` | `d48126cb8b95` | `ccccaf1eb25c` (checkout com alteracoes locais) |
| `lowcost-europa` | `0a1707e534d1` | `388860c6a167` (checkout limpo) |
| `fadego` | `98fbda932f00` | `2b3554ec6e07` (identificador da release ativa; verificar origem de build) |
| `Engenheira-reversa` | `429b17618917` | `8e9a7ee29566` (clone trial; REA FINAL separadamente) |

**NOTA:** o `main` diferir do checkout nao significa automaticamente que um servico esta avariado, nem que deve ser atualizado. A release em execucao pode ter sido intencionalmente fixada. Nao fazer `git pull` sem auditar.

## Estado da migracao

- **Confirmado:** Telegram Robot Leads `/opt/telegram-robot-leads/optin` e `archive/previous-telegram-python-env` ja dentro da instalacao. Os dois robots estavam `online` no PM2.
- **Confirmado:** PINK IPTV integrou a antiga pasta de provas `/srv/pink-iptv-device-proof` (4 558 049 280 bytes) em `/srv/projects/pink-iptv/tests/device-proof/` sem alterar o estado dos servicos nem as 6 modificacoes locais de Git. Git local configurado para ignorar esse diretorio; o `.gitignore` no GitHub foi alinhado. [Execucao #41702791325](https://github.com/martaxi-boss/VPS/actions/runs/41702791325).
- **Pendente:** integracao/referenciacao segura dos dados e credenciais privadas do Telegram Robot Leads; atualizacao final do PM2 e dados privados de `iptvpn-bot`; separacao e migracao de pastas do PINK, FADEGO, Ferrari, REA e Codex; validacao dos instaladores e desinstaladores.
- **Nao executar por atalho:** mover ou apagar pastas sem actualizar os caminhos de arranque, systemd/PM2, reverse proxies, backups, CI, permissões e referencias. Nao copiar segredos para GitHub.

## Higienizacao real verificada em 2026-11-03

| Componente | Limpeza efetuada | Recuperacao real de espaco | Prova |
| --- | --- | ---: | --- |
| Journal systemd / Ubuntu | Rotacao e remocao de registos antigos arquivados, limitando o conjunto a aproximadamente 350 MB | 307 937 280 bytes | [Actions #41703053896](https://github.com/martaxi-boss/VPS/actions/runs/41703053896) |
| Claude Server Commander (ambientes root e ubuntu) | Apenas as duas caches Puppeteer sem processos ativos; foram preservadas as configuracoes e pequenos ficheiros de historico | 825 438 208 bytes | [Actions #41703488947](https://github.com/martaxi-boss/VPS/actions/runs/41703488947) |
| Gradle do utilizador root | Removidas caches recompilaveis `caches/9.6.0` e `caches/build-cache-1`; preservados `caches/modules-2` e `wrapper` | 1 101 107 200 bytes | [Actions #41706630441](https://github.com/martaxi-boss/VPS/actions/runs/41706630441) |
| **Total das limpezas verificadas nesta fase** | **Sem desinstalar projetos** | **2 234 482 688 bytes** | Confirmado por leitura do disco |

A migracao de ficheiros PINK IPTV desta fase **nao libertou espaco**: foi uma mudanca atomica dentro do mesmo filesystem. Nao somar os 4,56 GB organizados como recuperacao de disco. Os processos PM2 e os servicos principais foram conferidos apos cada limpeza.

Continuam pendentes outros residuos e localizacoes soltas, especialmente dados privados de Telegram, provas antigas PINK (agora dentro do projeto), bibliotecas Android/Gradle partilhadas e versoes anteriores de FADEGO. Preservar ate serem auditadas individualmente.

## Arquivos adicionais organizados em 2026-11-03

Foram identificados por conteudo e movidos **sem apagar dados**, mantendo serviços e dois robos Telegram ativos:

| Projeto | Origem anterior na VPS | Destino dentro do projeto | Bytes reorganizados |
| --- | --- | --- | ---: |
| `pink-iptv` | `/srv/android002-validator-final-46fea6e` | `/srv/projects/pink-iptv/tests/archive/android002-validator-final-46fea6e` | 1 314 816 |
| `iptvpn-bot` | `/root/migration-20260923/iptvpn-bot-pre-final` | `/srv/projects/iptvpn-bot/archive/migration-20260923/iptvpn-bot-pre-final` | 12 288 |
| `lowcost-europa` | `/root/migration-preserved/home-lowcost-admin` | `/srv/projects/lowcost-europa/archive/migration-preserved/home-lowcost-admin` | 40 960 |

**Total reorganizado neste passo:** 1 368 064 bytes. **Espaco libertado por estas movimentacoes: 0 bytes** (mesmo disco). Fontes: [preflight e identificacao #41706859286](https://github.com/martaxi-boss/VPS/actions/runs/41706859286) e [execucao #41707116287](https://github.com/martaxi-boss/VPS/actions/runs/41707116287).

Os arquivos ficam ignorados no Git tanto na VPS como nos respetivos repositorios. As pastas raiz de migracao de 2026-09 continuam a existir com conteudo de outros projetos: NAO declarar que foram limpas por completo. Foi adicionado `docs/VPS_INSTALLATION.md` em `iptvpn-bot` e `lowcost-europa`; `pink-iptv` ja possuia documentacao, agora ampliada.

## Migracao fisica para pasta canonica — IPTV PN Bot

Em 2026-11-03, o checkout e os seus 82 612 224 bytes foram movidos fisicamente para `/srv/projects/iptvpn-bot`. O antigo `/root/iptvpn_bot` ficou apenas como **symlink temporario** para preservar as referencias antigas. O Python executou a partir do caminho canonico, os ficheiros Git permaneceram intactos e os dois processos Telegram mantiveram os mesmos PID e estado online. **Prova:** [Actions #41708170046](https://github.com/martaxi-boss/VPS/actions/runs/41708170046).

Uma primeira tentativa com teste de biblioteca inadequada falhou e foi revertida: [Actions #41707923562](https://github.com/martaxi-boss/VPS/actions/runs/41707923562). A repeticao corrigida terminou com codigo interno zero. A migracao **nao libertou bytes** por ter sido um rename no mesmo disco.

Ainda falta apontar a configuracao PM2 para o novo caminho, confirmar o arranque apos restart controlado e remover o symlink antigo. Os ficheiros privados em `/etc/iptvpn-bot` e `/root/project-secrets/iptvpn_bot` permanecem intactos e ainda externos. Nao considerar a desinstalacao apenas com remocao da pasta certificada.

O projeto `lowcost-europa` esta agora fisicamente em `/srv/projects/lowcost-europa` (117 411 840 bytes). As duas tentativas anteriores [#41708496093](https://github.com/martaxi-boss/VPS/actions/runs/41708496093) e [#41708984346](https://github.com/martaxi-boss/VPS/actions/runs/41708984346) fizeram rollback devido a Git exit 128 ao verificar com a identidade errada. A execucao [#41709236022](https://github.com/martaxi-boss/VPS/actions/runs/41709236022) verificou com a conta proprietaria e passou; o processo lowcost manteve PID 293428 e os dois robos mantiveram-se online. `/srv/lowcost-europa` e agora symlink de compatibilidade. Dados e segredos externos continuam pendentes.

## Migracao fisica para pasta canonica — PINK IPTV

O projeto `pink-iptv` esta fisicamente em `/srv/projects/pink-iptv` (4 815 273 984 bytes) desde 03-11-2026. O nome corresponde exatamente ao repositorio GitHub. A pasta anterior `/srv/pink-iptv` e agora um **symlink temporario** para evitar que os servicos percam os caminhos antigos. Os arquivos de teste Android, a base de codigo e as seis alteracoes locais Git foram preservados. PID do backend sem reinicio: 1146. [Prova #41709559974](https://github.com/martaxi-boss/VPS/actions/runs/41709559974). A mudanca de pasta **nao libertou espaco**, sendo um rename atomico no mesmo disco.

As unidades systemd, as configuracoes VPN e as referencias externas de deploy continuam a requerer atualizacao. Ate um novo arranque certificado, manter a ligacao antiga e nao declarar a desinstalacao integral pronta.

## Validacao conjunta de organizacao — 2026-11-03 20:10 UTC

O motor REA confirmou em leitura o estado atual, com `normalized_result.exit.code=0`, no [GitHub Actions #41709949401](https://github.com/martaxi-boss/VPS/actions/runs/41709949401).

| Repositorio | Pasta fisica canonica | Bytes | Ligacao antiga mantida |
| --- | --- | ---: | --- |
| `iptvpn-bot` | `/srv/projects/iptvpn-bot` | 82 624 512 | `/root/iptvpn_bot` |
| `lowcost-europa` | `/srv/projects/lowcost-europa` | 117 411 840 | `/srv/lowcost-europa` |
| `pink-iptv` | `/srv/projects/pink-iptv` | 4 815 273 984 | `/srv/pink-iptv` |

Os servicos PINK backend, PINK VPN, FADEGO, Low Cost, PM2, Nginx, PostgreSQL e SSH foram observados ativos. Os dois robos Telegram estavam `online`. `df -hT /`: **72G total, 57G ocupados, 16G livres, 79%**, valores arredondados.

Ainda existe `/opt/telegram-robot-leads` com componentes privados externos; FADEGO, Ferrari, REA e Codex nao foram migrados para a raiz canonica. As ligacoes antigas dos tres projetos sao **temporarias**: servicos e ferramentas de deploy ainda as referenciam. O utilizador nao deve fazer `rm` dessas pastas, nem declarar reinstalacao/desinstalacao independente pronta. Foram organizados arquivos adicionais e limpas apenas caches regeneraveis; nunca dados privados ou sessoes.

## Telegram Robot Leads — migracao da pasta canonica 03-11-2026

O projeto `telegram-robot-leads` foi fisicamente movido para `/srv/projects/telegram-robot-leads`. `/opt/telegram-robot-leads` passou a symlink temporario para os processos antigos. A instalacao inicial tinha 72 630 272 bytes; apos a substituicao dos caminhos locais e compilacao dos scripts, a pasta tinha 72 695 808 bytes. As duas sessoes e os dados de estado nao foram alterados. O PM2 permaneceu online com o PID **430721** e o bot independente `iptvpn_bot` com PID **1120**. Todos os servicos principais continuaram ativos.

Foram atualizados sete ficheiros do runtime (ecosystem, scripts de ativacao, higienizacao, relatorio, status, radar e instalador), sem alterar a logica de operacao. O codigo-fonte e a documentacao do repositorio GitHub `telegram-robot-leads` foram alinhados atraves do conector GitHub (separadamente da execucao pelo REA). A raiz fisica esta organizada, mas **a migracao nao esta completa**.

Pendencias e precaucoes:
- `/var/lib/telegram-robot-leads` (estado operacional) e `/root/project-secrets/telegram-robot-leads` (duas sessoes) continuam pastas reais exteriores; os modulos de runtime validam ausencia de symlink para essas pastas.
- O PM2 ainda utiliza a raiz antiga e os caminhos antigos de estado e vault; sera preciso um cutover coordenado com reinicio e verificacao de sessao, antes de remover a compatibilidade.
- O workflow de deploy legado do repo `VPS` contem os caminhos anteriores e SHA pinned; editar o proprio workflow em main desencadeia automaticamente deploy. **Nao ativar esse deploy desatualizado ate corrigir os caminhos e conferir o SHA.**
- Nao duplicar nem eliminar as sessoes; nao publicar arquivos privados no GitHub.

**Prova real REA:** [GitHub Actions #41711090273](https://github.com/martaxi-boss/VPS/actions/runs/41711090273) — exit zero, settlement quiesced e verificacoes de integridade. A mudança de pasta nao libertou espaco, apenas reorganizou dados existentes.

## Requisitos de instalacao e desinstalacao por projeto

Um projeto so esta **PRONTO PARA DESINSTALAR** quando possui um procedimento versionado que:
1. Identifica root canonico e SHA/release atualmente instalados.
2. Para apenas os seus processos, timers e unidades, sem afetar outras aplicacoes.
3. Preserva, exporta ou remove dados/sessoes/segredos conforme a escolha do proprietario.
4. Remove as referencias externas que efetivamente pertencem ao projeto (incluindo systemd, PM2, proxy, backups, contas e permissões onde apropriado).
5. Remove a pasta do projeto e verifica que nao existem residuos exclusivos.
6. Permite reinstalar a partir do GitHub e restaurar os dados de backup sem depender de pastas abandonadas.

Documento factual de acompanhamento. Atualizar apos cada migracao **validada** e nao mudar a arquitetura da ponte GitHub Actions/SSH nem instalar novos coordenadores.
