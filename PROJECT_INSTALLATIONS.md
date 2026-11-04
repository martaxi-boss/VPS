# Instalacoes da VPS por repositorio GitHub

**Auditoria factual:** 2026-11-03 19:11 UTC, Ubuntu VPS. **Evidencia:** https://github.com/martaxi-boss/VPS/actions/runs/41700745454.

> Este ficheiro e um mapa de instalacoes, nao uma declaracao de que todas as migracoes ja ocorreram. Nunca copiar valores de credenciais ou sessoes para o GitHub.

## Regra OBRIGATORIA do proprietario — uma pasta principal por instalacao

**Aplica-se a todas as instalacoes, antigas e novas. Nao e apenas uma preferencia de nomenclatura.**
O estado so e conforme quando cada instalacao autonoma tem uma **pasta principal fisica** em `/srv/projects/` e quando todos os componentes proprios estao dentro dela.

- **Um repositorio GitHub = uma raiz fisica independente**: `/srv/projects/<nome-exato-do-repositorio>/`, respeitando maiusculas, minusculas e hifens. Cada ferramenta/programa autonomo sem repositorio proprio tambem precisa de uma raiz identificada em `/srv/projects/<nome-da-instalacao>/`, ou de pertencer inequivocamente a uma instalacao de projeto existente.
- **Dentro da raiz**: codigo e releases, binarios/ferramentas exclusivas, fornecedores instalados, bibliotecas e dependencias especificas (`.venv`, `node_modules`, SDKs privados quando aplicavel), configuracoes e segredos do projeto, estado, sessoes, bases de dados proprias, ficheiros web/publicos do projeto, logs, backups, temporarios, caches, testes e artefactos. Organizar por subpastas, nao espalhar por `/opt`, `/home`, `/root`, `/var/www`, `/var/lib` ou outras localizacoes arbitrarias.
- **Independencia real**: projetos nao devem apontar para dependencias, fornecedores, sesssoes ou pastas privadas de outro projeto. Se dois projetos precisarem da mesma ferramenta autonoma, cada um tem a propria instalacao independente sob a respetiva raiz; nao apresentar uma instalacao partilhada como isolamento completo.
- **Links e aliases historicos**: permitidos apenas temporariamente para compatibilidade durante migracoes auditadas. Nao contam como instalacoes principais, e nao podem ficar como solucao final. Remover so depois de atualizar todas as referencias e validar arranque/reinicio do processo respetivo.
- **Unicas integracoes externas inevitaveis do Ubuntu**: caminhos geridos pelo proprio sistema, por exemplo executaveis e bibliotecas APT, ficheiros de unidades systemd em `/etc/systemd/system`, entradas Nginx em `/etc/nginx`, sockets, configuracoes de rede e servicos do sistema. **Sao integracoes do Ubuntu, nao outra instalacao da aplicacao**. Inventariar cada referencia com um proprietario. Nao colocar codigo, releases, runtime, segredos nem dados de aplicacoes nesses caminhos sob pretexto de excecao.
- Se uma ferramenta so funcionar mediante instalacao global APT, **identificar explicitamente a dependencia de sistema e a impossibilidade de a recolocar**, em vez de inventar independencia ou alterar ficheiros geridos pelo Ubuntu. Um requisito nao executavel dessa forma fica assinalado como pendente tecnico.
- Cada robo, quando usa PM2, deve ter estado/daemon e configuracoes independentes quando necessarios para garantir que arranque, paragem, reinicio e desinstalacao de um projeto nao afetam outro. Um PM2 global partilhado por dois robos nao cumpre a meta de independencia integral.
- Codigo, manifestos de dependencias, instaladores e templates de configuracao ficam versionados no repositorio correspondente. **Nunca** publicar sessoes, tokens, credenciais, ficheiros de estado, backups ou bases de dados privadas no GitHub.
- Nao efetuar `mv`, `rm -rf`, mudanca de unidade systemd, PM2 ou outro cutover em producao sem preflight e verificacao dos caminhos de arranque, permissoes, dependencias, rede, backups e integridade. Preservar dados e funcionamento. Migrar e validar **um projeto de cada vez**.
- Cada migracao exige **read-back real na VPS**: raiz fisica sem symlink, diretorios proprios, release/SHA, processo/servico, testes de arranque e reinicio, ausencia de referencias aos caminhos antigos e ausencia de efeitos nos restantes projetos.
- Um projeto so e declarado **CONFORME** quando nao subsistirem instalacoes autonomas nem dados proprios fora da sua pasta principal, salvo integracoes inevitaveis do Ubuntu explicitamente inventariadas. Ate la, o estado e **PENDENTE**, mesmo que o GitHub ou os testes CI estejam verdes.

**Desvios concretos ainda pendentes (inventario de 03-11-2026; requerem nova verificacao antes de agir):** REA FINAL em `/home/ubuntu/rea-final-runtime`; REA 6.8.0/upstream e evidencias fora da raiz; componentes Codex em `/home/ubuntu/codex-agent` e `codex-bridge`; Android SDK em `/opt/android-sdk` e ferramentas em `/opt/hopper`; `/root/.android` e `/root/.gradle`; configuracoes privadas externas do `iptvpn-bot`; configuracoes web e dados de `fadego` e `lowcost-europa`; PM2 global ainda partilhado; aliases antigos. **Nao apagar nem fundir** estes elementos sem atribuir proprietario e validar a respetiva migracao.

## Mapa real de instalacoes identificadas (nao normalizadas)

| Repositorio GitHub | Pasta principal atual | Componentes fora da pasta | Estado de alinhamento |
| --- | --- | --- | --- |
| `telegram-robot-leads` | `/srv/projects/telegram-robot-leads` (inclui `data/`, `private/`, `.venv/`, `optin/`) | `/opt/telegram-robot-leads` (symlink temporario), `/root/.pm2` (gestor global), script de ativacao antigo em `/usr/local/sbin` | Raiz, estado e as duas sessoes consolidados; PM2 usa raiz canonica, gestor PM2 ainda partilhado. |
| `iptvpn-bot` | `/srv/projects/iptvpn-bot` | `/root/iptvpn_bot` (ligacao temporaria), `/etc/iptvpn-bot`, `/root/project-secrets/iptvpn_bot`, PM2 global | Nome canonico atingido fisicamente; arranque PM2 e dados privados ainda externos. |
| `pink-iptv` | `/srv/projects/pink-iptv` | `/srv/pink-iptv` (ligacao temporaria), configuracao VPN e unidades do Ubuntu; provas em `/srv/projects/pink-iptv/tests/device-proof/` | Nome canonico atingido fisicamente; backend ativo, 6 alteracoes locais preservadas. |
| `fadego` | `/srv/projects/fadego` | `/srv/fadego-staging` (compatibilidade temporaria), `/var/www/fadego-preview`, unidade systemd | Instalacao fisica com nome correto e versao ativa interna; servico ainda aponta ao caminho anterior. |
| `lowcost-europa` | `/srv/projects/lowcost-europa` | `/srv/lowcost-europa` (ligacao temporaria), `/var/lib/lowcost-europa`, `/var/www/lowcost-europa`, segredos e timers | Instalacao fisica no nome canonico; servico e backups ainda usam caminho antigo. |
| `skill-universal` (Ferrari) | `/srv/projects/skill-universal` | `/home/ubuntu/.local/share/motor-ferrari` (compatibilidade temporaria), programas APT do Ubuntu | Instalacao fisica com nome correto, runtimes e ferramentas privadas integrados e motor importado com sucesso. |
| `Engenheira-reversa` | `/srv/projects/Engenheira-reversa` (Trial) | `/home/ubuntu/.local/share/rea-chatgpt-trial` (symlink temporario). REA FINAL e upstream 6.8.0 permanecem instalacoes distintas. | Trial fisicamente organizado, sem alteracao do motor REA FINAL. Os outros runtimes requerem identificacao separada. |
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
- **Pendente:** isolamento do daemon PM2 entre os dois robos; migracao de dados privados do `iptvpn-bot`; remocao segura de links antigos; inventario dos runtimes REA FINAL e Codex, mais testes de reinicio e desinstalacao. As pastas fisicas PINK, FADEGO e Ferrari ja estao em `/srv/projects/`.
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

Nota de auditoria historica: a instalacao de Telegram passou para raiz canonica e, posteriormente, o estado e as sessoes foram reunidos fisicamente em `data/` e `private/`. A pasta `/opt/telegram-robot-leads` e agora apenas symlink temporario. FADEGO e Ferrari tambem estao em `/srv/projects/`; REA FINAL e Codex ainda nao. Nao remover os links ate rever instaladores, servicos, backups e scripts de ativacao.

## Telegram Robot Leads — migracao da pasta canonica 03-11-2026

O projeto `telegram-robot-leads` foi fisicamente movido para `/srv/projects/telegram-robot-leads`. `/opt/telegram-robot-leads` passou a symlink temporario para os processos antigos. A instalacao inicial tinha 72 630 272 bytes; apos a substituicao dos caminhos locais e compilacao dos scripts, a pasta tinha 72 695 808 bytes. As duas sessoes e os dados de estado nao foram alterados. O PM2 permaneceu online com o PID **430721** e o bot independente `iptvpn_bot` com PID **1120**. Todos os servicos principais continuaram ativos.

Foram atualizados sete ficheiros do runtime (ecosystem, scripts de ativacao, higienizacao, relatorio, status, radar e instalador), sem alterar a logica de operacao. O codigo-fonte e a documentacao do repositorio GitHub `telegram-robot-leads` foram alinhados atraves do conector GitHub (separadamente da execucao pelo REA). A raiz fisica esta organizada, mas **a migracao nao esta completa**.

Pendencias e precaucoes:
- `/var/lib/telegram-robot-leads` (estado operacional) e `/root/project-secrets/telegram-robot-leads` (duas sessoes) continuam pastas reais exteriores; os modulos de runtime validam ausencia de symlink para essas pastas.
- O PM2 ainda utiliza a raiz antiga e os caminhos antigos de estado e vault; sera preciso um cutover coordenado com reinicio e verificacao de sessao, antes de remover a compatibilidade.
- O workflow de deploy legado do repo `VPS` contem os caminhos anteriores e SHA pinned; editar o proprio workflow em main desencadeia automaticamente deploy. **Nao ativar esse deploy desatualizado ate corrigir os caminhos e conferir o SHA.**
- Nao duplicar nem eliminar as sessoes; nao publicar arquivos privados no GitHub.

**Prova real REA:** [GitHub Actions #41711090273](https://github.com/martaxi-boss/VPS/actions/runs/41711090273) — exit zero, settlement quiesced e verificacoes de integridade. A mudança de pasta nao libertou espaco, apenas reorganizou dados existentes.

## Mudancas de pasta de FADEGO e Ferrari em 2026-11-03

FADEGO: `/srv/projects/fadego` (3 840 331 776 bytes). Ligacao `current` alterada de absoluta para relativa dentro do projeto. Processo PID 1144 e servicos sem interrupcao. [Prova #41713861548](https://github.com/martaxi-boss/VPS/actions/runs/41713861548).

Ferrari `skill-universal`: `/srv/projects/skill-universal` (13 517 766 656 bytes). Ambientes Python, ferramentas e runtimes privados mantidos; importacao do motor bem-sucedida com utilizador proprietario. [Prova #41714161162](https://github.com/martaxi-boss/VPS/actions/runs/41714161162).

Em ambos os casos os diretórios antigos sao symlinks temporarios para os instaladores existentes. Migracoes dentro do mesmo disco, **nenhum espaco libertado**. Ainda falta converter os caminhos de arranque e instalacao antes da eliminacao dos aliases.

## Instalação Trial REA e limpeza temporaria — 2026-11-03

O clone Trial do repositorio `martaxi-boss/Engenheira-reversa` e as suas ferramentas (2 529 660 928 bytes) foram movidos para `/srv/projects/Engenheira-reversa`. O caminho original e uma ligacao de compatibilidade; o Git mantem o mesmo origin, estado e dados. REA FINAL, original upstream e evidencias **nao foram movidos nem misturados com o Trial**. [Prova #41715190029](https://github.com/martaxi-boss/VPS/actions/runs/41715190029), exit zero com settlement observacional `unverifiable`.

Foi limpa uma extracao AppImage antiga, nao utilizada, em `/tmp`. Medicao de espaco livre: **356 188 160 bytes recuperados**, servicos e robos preservados. [Prova #41715432425](https://github.com/martaxi-boss/VPS/actions/runs/41715432425).

As releases antigas do FADEGO **nao foram eliminadas**: a primeira tentativa abortou sem alteracoes porque as verificacoes confundiram templates e codigo-fonte com potenciais dados privados. Nao contabilizar poupanca nessa area.

## Auditoria consolidada de 7 projetos — 2026-11-03 20:57 UTC

**Execucao REA read-only:** [Actions #41717303575](https://github.com/martaxi-boss/VPS/actions/runs/41717303575), `normalized_result.exit.code=0`, `settlement=quiesced`. A pasta `/srv/projects/` contem **sete instalacoes fisicas**, correspondentes aos seguintes nomes de repositorio, sem symlink na propria raiz:

| Repositorio | Bytes da instalacao na auditoria |
| --- | ---: |
| `iptvpn-bot` | 82 673 664 |
| `telegram-robot-leads` | 72 695 808 |
| `pink-iptv` | 4 815 273 984 |
| `lowcost-europa` | 117 411 840 |
| `fadego` | 3 840 327 680 |
| `skill-universal` | 13 652 721 664 |
| `Engenheira-reversa` (Trial, nao REA FINAL) | 2 529 660 928 |

Os **sete caminhos antigos ainda existem somente como ligacoes de compatibilidade** para preservar instaladores e processos antigos. Nao os remover nem declarar desinstalacao simples pronta ate verificar as referencias externas.

`fadego-staging.service`, `lowcost-europa.service` e `pink-iptv-backend.service` foram atualizados para os novos caminhos sob `/srv/projects/` e verificados pelo `systemd-analyze verify`, seguido de `systemctl daemon-reload`, **sem reiniciar** os processos e mantendo os PID originais: [Actions #41716531862](https://github.com/martaxi-boss/VPS/actions/runs/41716531862). O ambiente Python PINK teve 17 launchers corrigidos ([#41716056823](https://github.com/martaxi-boss/VPS/actions/runs/41716056823)) e o Low Cost teve 6 launchers corrigidos ([#41716321831](https://github.com/martaxi-boss/VPS/actions/runs/41716321831)). Testes de ferramentas de cada ambiente passaram.

Apos alteracoes de instalacao, Ferrari `current` passou a resolver para a release `c5b07ed225299ad80aa2d46c28441d17f281f695` na auditoria das 20:57 UTC. **Nao assumir que a release ativa e imutavel.** Os scripts de instalacao e o workflow manual `skill-universal` passaram a apontar para a pasta canonica, com CI [#41717025814](https://github.com/martaxi-boss/skill-universal/actions/runs/41717025814) SUCCESS. O workflow central Ferrari antigo ainda precisa de harmonizacao antes de eliminar compatibilidade.

**Disco:** 72G totais, 57G ocupados, 16G disponiveis, 79% de ocupacao segundo `df -hT`; 16 486 625 280 bytes disponiveis na leitura binaria.

**Limpeza adicional comprovada neste conjunto:** cache de extracao AppImage antiga sob `/tmp` eliminada, **356 188 160 bytes recuperados** em [Actions #41715432425](https://github.com/martaxi-boss/VPS/actions/runs/41715432425). **FADEGO mantem as nove releases originais**: o preflight de limpeza falhou e a tentativa posterior foi bloqueada; nao contabilizar poupanca das releases. Preservadas a versao ativa e as anteriores.

**Pendencias nao escondidas:** sessoes e estado dos robos fora das pastas, configuracoes privadas dos projetos, PM2 global e scripts que referenciam os caminhos antigos, ficheiros web/proxy e backups, REA FINAL original e upstream fora de `/srv/projects/`, Codex agent/bridge e ferramenta Android SDK. Os servicos e robos foram observados ativos, mas **nenhum projeto foi ainda certificado para uma desinstalacao independente apenas com apagamento da pasta**.

## Atualizacao confirmada — Telegram Robot Leads (2026-11-03, 21h30 UTC)

O robo ja inicia pelo caminho `/srv/projects/telegram-robot-leads/main.py`. A operacao REA [#41721220196](https://github.com/martaxi-boss/VPS/actions/runs/41721220196) substituiu **apenas** o processo PM2 deste projeto. O outro robo (`iptvpn_bot`, PID 1120) nao foi reiniciado.

A operacao REA [#41721810190](https://github.com/martaxi-boss/VPS/actions/runs/41721810190) executou o cutover fisico de:
- `/var/lib/telegram-robot-leads` → `/srv/projects/telegram-robot-leads/data`;
- `/root/project-secrets/telegram-robot-leads` → `/srv/projects/telegram-robot-leads/private`.

As duas sessoes foram verificadas por tamanho, inode e hash SHA-256 **sem imprimir conteudo nem valores**. Os arquivos externos originais deixaram de existir apos os `rename`; nao sao symlinks. Nove ficheiros ativos foram alterados apenas nos caminhos. O processo retomou `online` com PID 606651, PM2 guardou a configuracao, e o IPTV PN Bot permaneceu com o mesmo PID.

O codigo e a documentacao do GitHub `telegram-robot-leads` foram alinhados num commit unico `1e8c4e024cc3` (16 ficheiros), com CI [#41722257390 — SUCCESS](https://github.com/martaxi-boss/telegram-robot-leads/actions/runs/41722257390). Nenhum segredo ou sessao foi enviado ao GitHub.

**Ainda nao certificado como isolamento integral:** o PM2 daemon global `/root/.pm2` e usado pelos dois bots; ha um script legado em `/usr/local/sbin/telegram_leads_activate_20261020.py`, e um workflow VPS historico com caminhos antigos. Estes componentes exigem corte controlado antes de se retirar `/opt/telegram-robot-leads`.

## Higienizacao adicional verificada — cache pip e Ferrari npm (2026-11-03)

Duas operacoes de limpeza **distintas, medidas no filesystem** foram executadas via motor REA FINAL nesta continuacao, sem remover instalacoes:

| Origem | Limpeza | Disco efetivamente libertado | Prova |
| --- | --- | ---: | --- |
| Caches pip do utilizador `ubuntu` e do utilizador `root` | `python3 -m pip cache purge`, com validacao previa de identidade e caminho; nao elimina `.venv` | **75 702 272 bytes** | [Actions #41722028636](https://github.com/martaxi-boss/VPS/actions/runs/41722028636) |
| Ferrari `/srv/projects/skill-universal/.runtime/npm-cache/_cacache` | Script proprio `install/ferrari-cache-hygiene.py --apply`, executado como `ubuntu`; runtimes/REA/Apktool/Node/Java/Ruflo preservados | **326 848 512 bytes** | [Actions #41722397677](https://github.com/martaxi-boss/VPS/actions/runs/41722397677) |
| **Total desta continuacao** | **Caches regeneraveis apenas** | **402 550 784 bytes** | REA MCP: exit 0, settlement quiesced |

A cache Ferrari tinha sido limpa noutra fase e voltou a crescer devido a instalacoes/testes posteriores; **nao confundir esta limpeza de 326 MB com a primeira de 984 MB como se fossem o mesmo saldo final**. Espaco livre medido depois da limpeza Ferrari: **16 888 692 736 bytes** (valor pontual, pode mudar).

A verificacao das pastas fisicas em [#41720574656](https://github.com/martaxi-boss/VPS/actions/runs/41720574656) encontrou sete instalacoes em `/srv/projects/` e os servicos principais ativos. No momento da leitura, os dados e vault do Telegram ainda estavam fora; **foram migrados posteriormente** pelo cutover [#41721810190](https://github.com/martaxi-boss/VPS/actions/runs/41721810190), com duas sessoes preservadas. Usar sempre a verificacao mais recente, nao uma fotografia antiga.

O teste proposto de reinicio controlado do backend PINK foi bloqueado **antes de ser enviado a VPS** e nao foi executado. As unidades systemd estao configuradas para os caminhos canonicos e passaram validacao estatica, mas a certificacao de arranque apos reinicio continua pendente.

## Arquivo de integracoes Telegram obsoletas (2026-11-03)

O ativador de 20-10-2026 tinha uma janela temporal ja expirada e o timer `telegram-leads-activate-20261020.timer` permanecia ativo. Foi desativado, e o script + unit + timer foram movidos sem perda de ficheiros para `/srv/projects/telegram-robot-leads/archive/legacy/20261020-activation`. O processo Telegram Robot Leads permaneceu com PID 606651 e o IPTV PN Bot com PID 1120. **Prova:** [REA #41723648731](https://github.com/martaxi-boss/VPS/actions/runs/41723648731).

Quatro workflows Telegram antigos e o respetivo ativador de origem foram preservados em `docs/archive/legacy-telegram-202610/` e retirados das pastas executaveis do repo `VPS`. O workflow de deploy antigo usava `/opt/telegram-robot-leads` e SHAs historicos. O REA, o Supervisor e os workflows de outros projetos nao foram alterados.

Limpeza adicional confirmada: a cache de compilacao node-gyp `/home/ubuntu/.cache/node-gyp` foi eliminada apos verificacao de processos; **67 747 840 bytes** realmente libertados, restantes servicos inalterados. [REA #41722827037](https://github.com/martaxi-boss/VPS/actions/runs/41722827037).

## Verificacao conjunta apos limpeza — 2026-11-03 21:42 UTC

A auditoria real [REA/GitHub Actions #41724074992](https://github.com/martaxi-boss/VPS/actions/runs/41724074992), com processo interno exit zero e `settlement=quiesced`, confirmou **sete pastas fisicas reais** em `/srv/projects/`: `telegram-robot-leads`, `iptvpn-bot`, `pink-iptv`, `lowcost-europa`, `fadego`, `skill-universal` e `Engenheira-reversa` (Trial, NAO o REA FINAL).

Para o Telegram Robot Leads, `data/`, `private/` e `archive/legacy/20261020-activation/` existem fisicamente na raiz do projeto. As antigas diretorias externas de estado e sessoes nao existem. As **duas sessoes** estao presentes, o PM2 usa `/srv/projects/telegram-robot-leads` (PID **606651**) e o IPTV PN Bot permanece online (PID **1120**). O temporizador expirado e o servico antigo estao inativos, e os cinco ficheiros GitHub historicos foram arquivados em `docs/archive/legacy-telegram-202610/`.

Servicos verificados ativos: `fadego-staging`, `lowcost-europa`, `pink-iptv-backend`, `pink-vpn`, `nginx`, `postgresql@16-main`, `pm2-root` e `ssh`. Estado arredondado do disco: **72G total, 56G usados, 16G livres, 78%**.

**Pendencias reais (nao confundir com organizacao completa):** o PM2 global continua partilhado pelos dois bots, `iptvpn-bot` ainda tem configuracoes privadas externas e arranque num alias antigo, o REA FINAL (`/home/ubuntu/rea-final-runtime`) e os componentes Codex (`/home/ubuntu/codex-agent`) ainda nao foram reorganizados, e o Android SDK e integracoes Ubuntu exigem atribuicao de propriedade. Preservar aliases historicos ate confirmar todos os deployments/restarts. A independencia de desinstalacao com remocao de uma unica pasta **ainda nao esta certificada**.

## Requisitos de instalacao e desinstalacao por projeto

Um projeto so esta **PRONTO PARA DESINSTALAR** quando possui um procedimento versionado que:
1. Identifica root canonico e SHA/release atualmente instalados.
2. Para apenas os seus processos, timers e unidades, sem afetar outras aplicacoes.
3. Preserva, exporta ou remove dados/sessoes/segredos conforme a escolha do proprietario.
4. Remove as referencias externas que efetivamente pertencem ao projeto (incluindo systemd, PM2, proxy, backups, contas e permissões onde apropriado).
5. Remove a pasta do projeto e verifica que nao existem residuos exclusivos.
6. Permite reinstalar a partir do GitHub e restaurar os dados de backup sem depender de pastas abandonadas.

Documento factual de acompanhamento. Atualizar apos cada migracao **validada** e nao mudar a arquitetura da ponte GitHub Actions/SSH nem instalar novos coordenadores.
