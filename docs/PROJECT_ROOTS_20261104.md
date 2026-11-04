# VPS Ubuntu — mapa de instalacoes por pasta principal

**Ultima atualizacao factual:** 04-11-2026, 09:40 UTC. A auditoria de 01:20 [#41753274718](https://github.com/martaxi-boss/VPS/actions/runs/41753274718) e historica; a separacao REA FINAL/Trial foi verificada novamente em [#41786948401](https://github.com/martaxi-boss/VPS/actions/runs/41786948401) e [#41787208865](https://github.com/martaxi-boss/VPS/actions/runs/41787208865). Este documento nao declara certificacao de desinstalacao.

## Regra vinculativa

Cada repositorio GitHub implantado tem raiz fisica unica em `/srv/projects/<nome-do-repositorio>/`. Uma ferramenta autonoma sem repositorio pode ter raiz propria em `/srv/projects/<nome-da-ferramenta>/`. Codigo, fornecedores, dependencias proprias, dados, backups, logs e segredos ficam internos. **Nunca partilhar instalacoes privadas entre projetos.** Servicos e configuracoes exigidos por Ubuntu (systemd, Nginx, APT, rede, PostgreSQL quando servidor do sistema) sao integracoes externas obrigatoriamente inventariadas, nao outra instalacao da aplicacao.

## Diretorios fisicos presentes

| Pasta fisica em `/srv/projects/` | Origem/proprietario | Componentes integrados | Pendente antes da desinstalacao autonoma |
| --- | --- | --- | --- |
| `telegram-robot-leads/` | `martaxi-boss/telegram-robot-leads` | Codigo, `.venv`, `data`, `private`, arquivo antigo | Unico app no PM2 global; migrar estado/servico de forma independente e testar arranque |
| `iptvpn-bot/` | `martaxi-boss/iptvpn-bot` | Codigo, `.venv`, `config`, `private`, `data`, `.pm2`, `tools/pm2` privados | Teste de reboot da VPS, backup/restauro e desinstalacao autonoma; aliases externos ja retirados |
| `pink-iptv/` | `martaxi-boss/pink-iptv` | Backend, testes, `vpn/gateway`, `vpn/data` exclusivos; sistema VPN reiniciado | Fonte de runtime gateway e dependencias SDK Android por certificar; dois aliases VPN externos eliminados |
| `lowcost-europa/` | `martaxi-boss/lowcost-europa` | Codigo, `.venv`, `data`, `private`, `www`, `backups`, `bin` com 4 scripts de backup | Gunicorn reiniciado sem HOME antigo; testar backup/restauro, retirar aliases de dados e certificar desinstalacao |
| `fadego/` | `martaxi-boss/fadego` | Releases, `current`, dependencias, `www/preview`, backup Nginx | Certificar restart, DB/backups e alias `/srv/fadego-staging` |
| `skill-universal/` | `martaxi-boss/skill-universal` (Ferrari) | Motor, releases, ambientes, ferramentas, fornecedores privados | Validar consumidores do alias e apt global |
| `Engenheira-reversa/` | `martaxi-boss/Engenheira-reversa` (FINAL) | `original`, `runtime`, `evidence` e arquivo; checkout original do autor | Validar todos os consumidores dos aliases REA; nao alterar ponte nem fundir com Trial |
| `REA-Trial/` | Instalacao independente Trial | Checkout, ferramentas, evidencias, arquivo inativo de `/var/lib` e `/var/www`, estado OAuth antigo em `private/` protegido | Validar recuperabilidade e elegibilidade para eliminar arquivos; nao misturar com FINAL |
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

## Correcao posterior — 04-11-2026, 09:40 UTC

**IPTV PN Bot (separado):** o gestor PM2 proprio `/srv/projects/iptvpn-bot/{tools/pm2,.pm2}` foi criado e o processo movido [#41791449349](https://github.com/martaxi-boss/VPS/actions/runs/41791449349). O arranque e o lock privados foram testados [#41792220671](https://github.com/martaxi-boss/VPS/actions/runs/41792220671), os tres aliases `/root/iptvpn_bot`, `/etc/iptvpn-bot` e `/root/project-secrets/iptvpn_bot` retirados [#41792813752](https://github.com/martaxi-boss/VPS/actions/runs/41792813752), e os ficheiros GitHub sincronizados com o runtime [#41793256156](https://github.com/martaxi-boss/VPS/actions/runs/41793256156). PR [#4](https://github.com/martaxi-boss/iptvpn-bot/pull/4) integrada. O PM2 global `/root/.pm2` ainda existe mas serve **apenas Telegram Robot Leads**, pelo que este ultimo continua pendente de migração privada.

**PINK IPTV (VPN organizada):** dados de VPN em `vpn/data` [#41794005160](https://github.com/martaxi-boss/VPS/actions/runs/41794005160); codigo e configuracao privada do gateway fisicamente em `vpn/gateway` [#41805861212](https://github.com/martaxi-boss/VPS/actions/runs/41805861212). Os scripts e a unidade apontam para as pastas canonicas [#41806386638](https://github.com/martaxi-boss/VPS/actions/runs/41806386638). A VPN reiniciou e recuperou o socket de controlo [#41806890747](https://github.com/martaxi-boss/VPS/actions/runs/41806890747). Os aliases `/etc/pink-vpn` e `/var/lib/pink-vpn` foram removidos [#41807754045](https://github.com/martaxi-boss/VPS/actions/runs/41807754045), mantendo os servicos. A PR [#79](https://github.com/martaxi-boss/pink-iptv/pull/79) versionou o modelo da unidade. Scripts do gateway ainda estao excluidos do Git enquanto nao forem revistos para reproducibilidade sem segredos.

**Low Cost (higiene adicional):** o Gunicorn reiniciou sem referencias ao antigo HOME [#41795057413](https://github.com/martaxi-boss/VPS/actions/runs/41795057413); quarto script de backup consolidado na pasta `bin` [#41795556638](https://github.com/martaxi-boss/VPS/actions/runs/41795556638) e alias externo retirado [#41796213331](https://github.com/martaxi-boss/VPS/actions/runs/41796213331). Falta restauracao de backup validada e eliminacao dos aliases de dados seguros.

**Regra nao negociavel:** este mapa nao certifica desinstalacao independente de todos os projetos. Continuam pendentes o PM2 privado do Telegram Robot Leads, SDKs usados por mais de um projeto, os residuos REA nao classificados e os testes de restauro/reboot. Configuracoes Ubuntu em `/etc/systemd/system`, `/etc/nginx`, `/etc/wireguard` e sockets temporarios em `/run` sao integracoes do sistema, nao uma segunda instalacao do projeto.

## REA Trial — residuos externos fisicamente arquivados em 04-11-2026

A auditoria [#41808426095](https://github.com/martaxi-boss/VPS/actions/runs/41808426095) confirmou que os serviços antigos `rea-reversa-mcp` e `rea-mcp-oauth` estavam inativos, sem consumidores em Nginx/systemd/cron detetados para os caminhos que foram objeto desta migração. A execução [#41808880058](https://github.com/martaxi-boss/VPS/actions/runs/41808880058) moveu os dados históricos antes em `/var/lib/rea-reversa` para `/srv/projects/REA-Trial/archive/legacy-rea-reversa-state` e os ficheiros ACME antes em `/var/www/rea-reversa-acme` para `/srv/projects/REA-Trial/archive/legacy-rea-reversa-acme`, preservando propriedade, modos, inodes e serviços. **Nao foram apagados os dados nem deixadas ligacoes na origem.**

A execução [#41809062170](https://github.com/martaxi-boss/VPS/actions/runs/41809062170) confirmou a transferência física do estado OAuth antigo e protegido para `/srv/projects/REA-Trial/private/legacy-rea-mcp-oauth`, com permissões e UID/GID originais; os caminhos anteriores `/var/lib/rea-mcp-oauth` e `/var/lib/private/rea-mcp-oauth` foram retirados. Nenhum segredo foi aberto ou exportado. O projeto `Engenheira-reversa` (REA FINAL) permanece separado.

Os diretórios ficam preservados para auditoria/recuperação e **nao podem ser eliminados automaticamente** até certificação de que não contêm dados ou provas necessárias. Os movimentos no mesmo disco libertaram 0 bytes por remoção de ficheiros.
