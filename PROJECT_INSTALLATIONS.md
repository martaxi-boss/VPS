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
| `telegram-robot-leads` | `/opt/telegram-robot-leads` | `/var/lib/telegram-robot-leads`, `/root/project-secrets/telegram-robot-leads`, PM2 global | Nome correto; instalacao ainda dispersa. Opt-in e ambiente Python antigo ja foram integrados na pasta do projeto. |
| `iptvpn-bot` | `/root/iptvpn_bot` | `/etc/iptvpn-bot`, `/root/project-secrets/iptvpn_bot`, PM2 global | Nome diferente; dados privados externos. |
| `pink-iptv` | `/srv/pink-iptv` | Configuracao VPN e unidades do Ubuntu; provas de testes ja integradas em `/srv/pink-iptv/tests/device-proof/` | Nome correto; 4,56 GB de testes consolidados em 03-11-2026. Checkout com alteracoes locais, preservado. |
| `fadego` | `/srv/fadego-staging` | `/var/www/fadego-preview`, unidade systemd e servicos partilhados | Nome diferente; versoes em `releases/`, `current` aponta para uma release ativa. |
| `lowcost-europa` | `/srv/lowcost-europa` | `/var/lib/lowcost-europa`, `/var/www/lowcost-europa`, utilizador de administracao e timers | Nome correto; algumas dependencias e configuracoes externas. |
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
- **Confirmado:** PINK IPTV integrou a antiga pasta de provas `/srv/pink-iptv-device-proof` (4 558 049 280 bytes) em `/srv/pink-iptv/tests/device-proof/` sem alterar o estado dos servicos nem as 6 modificacoes locais de Git. Git local configurado para ignorar esse diretorio; o `.gitignore` no GitHub foi alinhado. [Execucao #41702791325](https://github.com/martaxi-boss/VPS/actions/runs/41702791325).
- **Pendente:** integracao/referenciacao segura dos dados e credenciais privadas do Telegram Robot Leads; alinhamento do `iptvpn-bot`; separacao e migracao de pastas do PINK, FADEGO, Ferrari, REA e Codex; validacao dos instaladores e desinstaladores.
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

## Requisitos de instalacao e desinstalacao por projeto

Um projeto so esta **PRONTO PARA DESINSTALAR** quando possui um procedimento versionado que:
1. Identifica root canonico e SHA/release atualmente instalados.
2. Para apenas os seus processos, timers e unidades, sem afetar outras aplicacoes.
3. Preserva, exporta ou remove dados/sessoes/segredos conforme a escolha do proprietario.
4. Remove as referencias externas que efetivamente pertencem ao projeto (incluindo systemd, PM2, proxy, backups, contas e permissões onde apropriado).
5. Remove a pasta do projeto e verifica que nao existem residuos exclusivos.
6. Permite reinstalar a partir do GitHub e restaurar os dados de backup sem depender de pastas abandonadas.

Documento factual de acompanhamento. Atualizar apos cada migracao **validada** e nao mudar a arquitetura da ponte GitHub Actions/SSH nem instalar novos coordenadores.
