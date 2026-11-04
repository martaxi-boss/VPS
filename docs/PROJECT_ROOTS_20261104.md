# VPS Ubuntu — mapa de instalacoes por pasta principal

**Ultima atualizacao factual:** 04-11-2026, 07:05 UTC. A auditoria de 01:20 [#41753274718](https://github.com/martaxi-boss/VPS/actions/runs/41753274718) e historica; a separacao REA FINAL/Trial foi verificada novamente em [#41786948401](https://github.com/martaxi-boss/VPS/actions/runs/41786948401) e [#41787208865](https://github.com/martaxi-boss/VPS/actions/runs/41787208865). Este documento nao declara certificacao de desinstalacao.

## Regra vinculativa

Cada repositorio GitHub implantado tem raiz fisica unica em `/srv/projects/<nome-do-repositorio>/`. Uma ferramenta autonoma sem repositorio pode ter raiz propria em `/srv/projects/<nome-da-ferramenta>/`. Codigo, fornecedores, dependencias proprias, dados, backups, logs e segredos ficam internos. **Nunca partilhar instalacoes privadas entre projetos.** Servicos e configuracoes exigidos por Ubuntu (systemd, Nginx, APT, rede, PostgreSQL quando servidor do sistema) sao integracoes externas obrigatoriamente inventariadas, nao outra instalacao da aplicacao.

## Diretorios fisicos presentes

| Pasta fisica em `/srv/projects/` | Origem/proprietario | Componentes integrados | Pendente antes da desinstalacao autonoma |
| --- | --- | --- | --- |
| `telegram-robot-leads/` | `martaxi-boss/telegram-robot-leads` | Codigo, `.venv`, `data`, `private`, arquivo antigo | PM2 ainda partilhado; links e arranque automatico |
| `iptvpn-bot/` | `martaxi-boss/iptvpn-bot` | Codigo, `.venv`, `config`, `private` | PM2 global usa `/root/iptvpn_bot/start.sh`; aliases historicos |
| `pink-iptv/` | `martaxi-boss/pink-iptv` | Backend, testes/dispositivo, dependencias proprias | Certificar restart, VPN/Android e aliases |
| `lowcost-europa/` | `martaxi-boss/lowcost-europa` | Codigo, `.venv`, `data`, `private`, `www`, `backups`, `bin` com 3 scripts de backup | Scripts de backup ja internos; testar backup/restauro, retirar aliases de dados e configurar desinstalacao autonoma |
| `fadego/` | `martaxi-boss/fadego` | Releases, `current`, dependencias, `www/preview`, backup Nginx | Certificar restart, DB/backups e alias `/srv/fadego-staging` |
| `skill-universal/` | `martaxi-boss/skill-universal` (Ferrari) | Motor, releases, ambientes, ferramentas, fornecedores privados | Validar consumidores do alias e apt global |
| `Engenheira-reversa/` | `martaxi-boss/Engenheira-reversa` (FINAL) | `original`, `runtime`, `evidence` e arquivo; checkout original do autor | Validar todos os consumidores dos aliases REA; nao alterar ponte nem fundir com Trial |
| `REA-Trial/` | Instalacao independente Trial | Checkout, ferramentas, evidencias e ficheiros privados proprios | Validar aliases apenas do Trial; nunca misturar com FINAL |
| `hopper/` | Ferramenta autonoma Hopper | `bin`, `lib` | Confirmar consumidores de `/opt/hopper` antes de remover alias |
| `android-sdk/` | Ferramenta autonoma Android SDK | SDK, estado `state/root-android`, cache `cache/root-gradle` | Verificar consumidores e separar SDK por projeto quando exigido |
| `Codex/` | `martaxi-boss/Codex` | Pacote Codex existente, `archive/legacy-bridge` | Remover aliases historicos apos atualizar workflows; nao criar coordenador VPS |

**Provas dos novos movimentos (2026-11-04):**
- Hopper [#41749540607](https://github.com/martaxi-boss/VPS/actions/runs/41749540607);
- Low Cost web [#41750334632](https://github.com/martaxi-boss/VPS/actions/runs/41750334632), dados e segredos [#41751694306](https://github.com/martaxi-boss/VPS/actions/runs/41751694306), configuracao ambiental [#41753483523](https://github.com/martaxi-boss/VPS/actions/runs/41753483523);
- IPTV PN Bot config/privado [#41751752478](https://github.com/martaxi-boss/VPS/actions/runs/41751752478);
- FADEGO web [#41752269362](https://github.com/martaxi-boss/VPS/actions/runs/41752269362), corte Nginx [#41753229953](https://github.com/martaxi-boss/VPS/actions/runs/41753229953) e remocao do alias web [#41753564391](https://github.com/martaxi-boss/VPS/actions/runs/41753564391);
- Android SDK [#41752331633](https://github.com/martaxi-boss/VPS/actions/runs/41752331633) e diretorios de estado `root` [#41752662613](https://github.com/martaxi-boss/VPS/actions/runs/41752662613);
- Codex fisico [#41751463892](https://github.com/martaxi-boss/VPS/actions/runs/41751463892), realinhamento para repo `Codex` [#41752751888](https://github.com/martaxi-boss/VPS/actions/runs/41752751888);
- Low Cost Nginx [#41753196864](https://github.com/martaxi-boss/VPS/actions/runs/41753196864), systemd [#41753692430](https://github.com/martaxi-boss/VPS/actions/runs/41753692430).

Todos os movimentos foram dentro do mesmo filesystem e **nao libertaram gigabytes**. Os links historicos nao sao copias fisicas da instalacao. As mudancas nao justificam reclamar independencia completa sem validar os reinicios e remover os links restantes.

## Caminhos externos historicos e o unico runtime autonomo ainda partilhado

A auditoria anterior #41753274718 ainda encontrava os tres caminhos REA FINAL como diretorios fisicos fora da raiz. **Esse estado foi corrigido** em [#41785168890](https://github.com/martaxi-boss/VPS/actions/runs/41785168890). A leitura real [#41786948401](https://github.com/martaxi-boss/VPS/actions/runs/41786948401) confirmou que os tres caminhos anteriores sao agora apenas symlinks para o projeto FINAL. `/etc/lowcost-europa` e tambem alias para `private/systemd-env`.

| Caminho externo | Identificacao | Estado |
| --- | --- | --- |
| `/home/ubuntu/rea-original-upstream-680` | Codigo do REA FINAL, pacote do autor versao 6.8.0 | **ALIAS**, fisico em `/srv/projects/Engenheira-reversa/original`; nao apagar o motor |
| `/home/ubuntu/rea-final-runtime` | Dependencias/fornecedores exclusivos do FINAL | **ALIAS**, fisico em `/srv/projects/Engenheira-reversa/runtime` |
| `/home/ubuntu/rea-original-upstream-680-evidence` | Evidencias do REA FINAL | **ALIAS**, fisico em `/srv/projects/Engenheira-reversa/evidence` |
| `/root/.pm2` | Daemon PM2 partilhado pelos dois robos Telegram | **PENDENTE** separar daemons e unidades systemd, sem duplicar processos |

O REA FINAL original tem numero de pacote 6.8.0. **Nao e prova de uma instalacao legacy inutil**: o README atual de `Engenheira-reversa` identifica esse checkout como motor FINAL. O repositorio `Engenheira-reversa` identifica o FINAL; a instalacao `REA-Trial` e fisicamente independente.

A auditoria PM2 [#41752853430](https://github.com/martaxi-boss/VPS/actions/runs/41752853430) confirmou `iptvpn_bot` e `telegram-robot-leads` online no PM2 global; a mudanca de pastas, so por si, nao substitui o cutover de daemon, o save e o boot automatico.

## Higienizacao comprovada

[Workflow Owner #41751404962](https://github.com/martaxi-boss/VPS/actions/runs/41751404962): 596 ficheiros de cache antigos removidos, **3 555 328 bytes de blocos alocados** removidos, aumento liquido pontual de **425 984 bytes** no espaco livre, variando por operacoes simultaneas. Nenhuma sessao, base de dados, projeto, fornecedor instalado ou processo foi removido.

## Estado dos servicos e disco

Auditoria [#41753274718](https://github.com/martaxi-boss/VPS/actions/runs/41753274718): dez diretorios fisicos reais acima e servicos `nginx`, `ssh`, `fadego-staging`, `lowcost-europa`, `pink-iptv-backend`, `pink-vpn`, `pm2-root`, `postgresql@16-main` **active**. Nginx `-t` valido. Disco total **76 887 154 688 bytes**, livres **16 431 222 784 bytes** naquele instante; estes valores mudam.

## Requisitos finais de encerramento por projeto

1. Corrigir o workflow/instalador do repo para usar a raiz propria, com release, ambiente e fornecedores exclusivos.
2. Fazer o cutover de todos os processos e integracoes externas apenas desse projeto, sem tocar nos outros.
3. Preservar e comprovar sessoes, dados, DB, segredos, backups e hashes antes de eliminar qualquer alias.
4. Testar reinicio do projeto e ciclo de arranque automatico, comparar estado funcional e servicos de terceiros.
5. Remover aliases usados no passado e registos exclusivos no Ubuntu; fazer uma nova procura de residuos.
6. Disponibilizar instalador e desinstalador isolados versionados no GitHub, testando num ambiente de recuperacao.
7. Marcar **PRONTO A DESINSTALAR** apenas com provas reais destas etapas. Hoje **nenhum projeto recebeu esta certificacao completa**.

**Nao fazer `rm -rf` das pastas principais como atalho**. O objetivo final e precisamente nao deixar recursos orfaos nem danificar projetos vizinhos.

## Consolidacao Low Cost de 06:44 a 07:00 UTC

A Low Cost deixou de ter fisicamente em `/usr/local/sbin` os tres scripts exclusivos de backup. O codigo foi movido para `/srv/projects/lowcost-europa/bin` [#41788166561](https://github.com/martaxi-boss/VPS/actions/runs/41788166561); referencias a dados, segredos e backups dentro dos scripts foram normalizadas [#41788336141](https://github.com/martaxi-boss/VPS/actions/runs/41788336141); as tres unidades systemd foram atualizadas para esse `bin/` [#41788761333](https://github.com/martaxi-boss/VPS/actions/runs/41788761333). As ligacoes antigas dos tres scripts em `/usr/local/sbin` foram **eliminadas**, com auditoria de consumidores e preservacao dos servicos [#41788992667](https://github.com/martaxi-boss/VPS/actions/runs/41788992667).

As unidades weekly discovery, catalog maintenance e affiliate report tambem foram corrigidas para a raiz fisica [#41787555837](https://github.com/martaxi-boss/VPS/actions/runs/41787555837) e para o `EnvironmentFile` interno [#41787942887](https://github.com/martaxi-boss/VPS/actions/runs/41787942887). O repositorio fonte foi alinhado pelas PRs [#191](https://github.com/martaxi-boss/lowcost-europa/pull/191) e [#192](https://github.com/martaxi-boss/lowcost-europa/pull/192).

**Nao certificado ainda:** restauracao real de backup, remocao dos aliases de `data/`, `private/` e `backups/` usados por utilitarios genericos, desinstalacao integral e separacao dos daemons PM2 dos dois robos.
