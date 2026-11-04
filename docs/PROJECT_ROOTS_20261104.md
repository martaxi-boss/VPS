# VPS Ubuntu — mapa de instalacoes por pasta principal

**Ultima atualizacao factual:** 04-11-2026, apos migracao PM2 e arquivo historico. A auditoria de 01:20 [#41753274718](https://github.com/martaxi-boss/VPS/actions/runs/41753274718) e historica; a separacao REA FINAL/Trial foi verificada novamente em [#41786948401](https://github.com/martaxi-boss/VPS/actions/runs/41786948401) e [#41787208865](https://github.com/martaxi-boss/VPS/actions/runs/41787208865). Este documento nao declara certificacao de desinstalacao.

## Regra vinculativa

Cada repositorio GitHub implantado tem raiz fisica unica em `/srv/projects/<nome-do-repositorio>/`. Uma ferramenta autonoma sem repositorio pode ter raiz propria em `/srv/projects/<nome-da-ferramenta>/`. Codigo, fornecedores, dependencias proprias, dados, backups, logs e segredos ficam internos. **Nunca partilhar instalacoes privadas entre projetos.** Servicos e configuracoes exigidos por Ubuntu (systemd, Nginx, APT, rede, PostgreSQL quando servidor do sistema) sao integracoes externas obrigatoriamente inventariadas, nao outra instalacao da aplicacao.

## Diretorios fisicos presentes

| Pasta fisica em `/srv/projects/` | Origem/proprietario | Componentes integrados | Pendente antes da desinstalacao autonoma |
| --- | --- | --- | --- |
| `telegram-robot-leads/` | `martaxi-boss/telegram-robot-leads` | Codigo, `.venv`, `data`, `private`, `tools/pm2`, `.pm2` e logs de processo proprios; unidade systemd com fonte dentro do projeto | PM2 proprio ativo e boot enabled; testar reboot e restauracao, retirar alias `/opt/telegram-robot-leads` |
| `iptvpn-bot/` | `martaxi-boss/iptvpn-bot` | Codigo, `.venv`, `config`, `private`, `data`, `.pm2`, `tools/pm2` privados | Teste de reboot da VPS, backup/restauro e desinstalacao autonoma; aliases externos ja retirados |
| `pink-iptv/` | `martaxi-boss/pink-iptv` | Backend, testes, `vpn/gateway`, `vpn/data` exclusivos; sistema VPN reiniciado | Fonte de runtime gateway e dependencias SDK Android por certificar; dois aliases VPN externos eliminados |
| `lowcost-europa/` | `martaxi-boss/lowcost-europa` | Codigo, `.venv`, `data`, `private`, `www`, `backups`, `bin` com 4 scripts de backup | Gunicorn reiniciado sem HOME antigo; testar backup/restauro, retirar aliases de dados e certificar desinstalacao |
| `fadego/` | `martaxi-boss/fadego` | Releases, `current`, dependencias, `www/preview`, backup Nginx | Certificar restart, DB/backups e alias `/srv/fadego-staging` |
| `skill-universal/` | `martaxi-boss/skill-universal` (Ferrari) | Motor, releases, ambientes, ferramentas, fornecedores privados | Validar consumidores do alias e apt global |
| `Engenheira-reversa/` | `martaxi-boss/Engenheira-reversa` (FINAL) | `original`, `runtime`, `evidence` e arquivo; checkout original do autor | Validar todos os consumidores dos aliases REA; nao alterar ponte nem fundir com Trial |
| `REA-Trial/` | Instalacao independente Trial | Checkout, ferramentas, evidencias, arquivos REA antigos e estado OAuth proprio em `private/` | Validar restauro isolado; nunca misturar com FINAL |
| `hopper/` | Ferramenta autonoma Hopper | `bin`, `lib` | Confirmar consumidores de `/opt/hopper` antes de remover alias |
| `android-sdk/` | Ferramenta autonoma Android SDK | SDK, estado `state/root-android`, cache `cache/root-gradle` | Verificar consumidores e separar SDK por projeto quando exigido |
| `Codex/` | `martaxi-boss/Codex` | Pacote Codex existente, `archive/legacy-bridge` | Remover aliases historicos apos atualizar workflows; nao criar coordenador VPS |
| `VPS/` | `martaxi-boss/VPS` (infraestrutura) | Arquivo retirado do PM2 global e unidade systemd obsoleta, sem dependencias partilhadas ativas | Atribuir historicos sem dono conhecido; nao usar esta pasta para instalar programas de outros projetos |

**Provas dos novos movimentos (2026-11-04):**
- Hopper [#41749540607](https://github.com/martaxi-boss/VPS/actions/runs/41749540607);
- Low Cost web [#41750334632](https://github.com/martaxi-boss/VPS/actions/runs/41750334632), dados e segredos [#41751694306](https://github.com/martaxi-boss/VPS/actions/runs/41751694306), configuracao ambiental [#41753483523](https://github.com/martaxi-boss/VPS/actions/runs/41753483523);
- IPTV PN Bot config/privado [#41751752478](https://github.com/martaxi-boss/VPS/actions/runs/41751752478);
- FADEGO web [#41752269362](https://github.com/martaxi-boss/VPS/actions/runs/41752269362), corte Nginx [#41753229953](https://github.com/martaxi-boss/VPS/actions/runs/41753229953) e remocao do alias web [#41753564391](https://github.com/martaxi-boss/VPS/actions/runs/41753564391);
- Android SDK [#41752331633](https://github.com/martaxi-boss/VPS/actions/runs/41752331633) e diretorios de estado `root` [#41752662613](https://github.com/martaxi-boss/VPS/actions/runs/41752662613);
- Codex fisico [#41751463892](https://github.com/martaxi-boss/VPS/actions/runs/41751463892), realinhamento para repo `Codex` [#41752751888](https://github.com/martaxi-boss/VPS/actions/runs/41752751888);
- Low Cost Nginx [#41753196864](https://github.com/martaxi-boss/VPS/actions/runs/41753196864), systemd [#41753692430](https://github.com/martaxi-boss/VPS/actions/runs/41753692430).

Todos os movimentos foram dentro do mesmo filesystem e **nao libertaram gigabytes**. Os links historicos nao sao copias fisicas da instalacao. As mudancas nao justificam reclamar independencia completa sem validar os reinicios e remover os links restantes.

## Caminhos externos historicos e integracoes restantes

A auditoria anterior #41753274718 ainda encontrava os tres caminhos REA FINAL como diretorios fisicos fora da raiz. **Esse estado foi corrigido** em [#41785168890](https://github.com/martaxi-boss/VPS/actions/runs/41785168890). A leitura real [#41786948401](https://github.com/martaxi-boss/VPS/actions/runs/41786948401) confirmou que os tres caminhos anteriores sao agora apenas symlinks para o projeto FINAL. `/etc/lowcost-europa` e tambem alias para `private/systemd-env`.

| Caminho externo | Identificacao | Estado |
| --- | --- | --- |
| `/home/ubuntu/rea-original-upstream-680` | Codigo do REA FINAL, pacote do autor versao 6.8.0 | **ALIAS**, fisico em `/srv/projects/Engenheira-reversa/original`; nao apagar o motor |
| `/home/ubuntu/rea-final-runtime` | Dependencias/fornecedores exclusivos do FINAL | **ALIAS**, fisico em `/srv/projects/Engenheira-reversa/runtime` |
| `/home/ubuntu/rea-original-upstream-680-evidence` | Evidencias do REA FINAL | **ALIAS**, fisico em `/srv/projects/Engenheira-reversa/evidence` |
| `/root/.pm2` | PM2 global antigo | **REMOVIDO FISICAMENTE** em [#41814206650](https://github.com/martaxi-boss/VPS/actions/runs/41814206650); arquivos por projeto [#41814439051](https://github.com/martaxi-boss/VPS/actions/runs/41814439051); unidade `pm2-root.service` retirada [#41814735028](https://github.com/martaxi-boss/VPS/actions/runs/41814735028). Ambos os robos usam PM2 privados |

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

## Isolamento real do PM2 dos dois robos e higiene REA — 04-11-2026

- O **IPTV PN Bot** tem binarios, processos, logs, estado PM2 e ficheiros privados dentro de `/srv/projects/iptvpn-bot/`; `pm2-iptvpn-bot.service` esta ativo e enabled. Prova [#41791449349](https://github.com/martaxi-boss/VPS/actions/runs/41791449349), fonte [PR #4](https://github.com/martaxi-boss/iptvpn-bot/pull/4).
- O **Telegram Robot Leads** tem PM2 7.0.4 privado [#41812493196](https://github.com/martaxi-boss/VPS/actions/runs/41812493196); preparacao isolada [#41813129459](https://github.com/martaxi-boss/VPS/actions/runs/41813129459); processo reiniciado para gestor proprio (PID 687619), serviço ativo e enabled, com global parado/disabled [#41813373759](https://github.com/martaxi-boss/VPS/actions/runs/41813373759). Fonte [PR #54](https://github.com/martaxi-boss/telegram-robot-leads/pull/54). A logica do robo nao foi editada.
- O diretorio `/root/.pm2` foi movido sem perda de 17 ficheiros para o arquivo de infraestrutura `/srv/projects/VPS/archive/` [#41814206650](https://github.com/martaxi-boss/VPS/actions/runs/41814206650). Logs dos dois robos foram redistribuidos fisicamente por origem, e a copia mista do snapshot foi dividida e eliminada [#41814439051](https://github.com/martaxi-boss/VPS/actions/runs/41814439051). Registos de origem nao comprovada permanecem sob VPS, como arquivo inativo; a unidade global foi retirada e arquivada [#41814735028](https://github.com/martaxi-boss/VPS/actions/runs/41814735028).
- O REA Trial recebeu exclusivamente os ficheiros de estado/acme [#41808880058](https://github.com/martaxi-boss/VPS/actions/runs/41808880058) e o OAuth antigo [#41809062170](https://github.com/martaxi-boss/VPS/actions/runs/41809062170). O REA FINAL continua fisicamente independente.

**Pendentes:** o alias `/opt/telegram-robot-leads` continua presente: ha referencias em backups antigos do próprio projeto, embora não exista uma segunda instalação física. A remocao automatizada foi bloqueada antes de ser executada; nao declarar eliminado. Restam os aliases de Android/Gradle, Hopper, Codex, REA FINAL e Low Cost, e o pacote PM2 global `/usr/lib/node_modules/pm2`, que requer auditoria de consumidores antes de eventual remocao. Reboot completo, backup/restauro e testes de desinstalacao ainda nao certificam 100%.

## Atualizacao verificada — 04-11-2026, 11:55 UTC

- **IPTV PN Bot:** os dois scripts globais antigos `scripts/pm2-start-all.sh` e `scripts/home-cleanup.sh` foram retirados do GitHub na [PR #5](https://github.com/martaxi-boss/iptvpn-bot/pull/5), commit `de152539a839c544a4eb802197c7114c823efc96`, e fisicamente da VPS em [#41821186405](https://github.com/martaxi-boss/VPS/actions/runs/41821186405). Testes de integridade mantiveram os dois robos e servicos ativos. Foram eliminados 7 323 bytes de **conteudo**, nao uma medicao de blocos livres.
- **Telegram Robot Leads:** a [PR #55](https://github.com/martaxi-boss/telegram-robot-leads/pull/55), commit `99c106022ef9e0691c05d74278dce8fd9791b8e8`, retirou as invocacoes do executavel PM2 global dos scripts de ativacao/diagnostico. A [execucao #41822433649](https://github.com/martaxi-boss/VPS/actions/runs/41822433649) sincronizou quatro ficheiros na VPS e passou 7 testes sem alterar os PIDs dos robos. A [execucao #41823509430](https://github.com/martaxi-boss/VPS/actions/runs/41823509430) retirou a copia obsoleta `optin/scripts/lead_health.py` (10 604 bytes de conteudo) e redirecionou o antigo script de estado para a versao canonica. A repeticao [#41824338142](https://github.com/martaxi-boss/VPS/actions/runs/41824338142) foi bloqueada por preflight de hash, sem alterar dados.
- **PM2 global:** a auditoria [#41822679529](https://github.com/martaxi-boss/VPS/actions/runs/41822679529) encontrou o pacote npm 7.0.4 ainda em `/usr/lib/node_modules/pm2` (~24 756 KiB), com comandos globais ligados a ele. A tentativa de o retirar [#41824721522](https://github.com/martaxi-boss/VPS/actions/runs/41824721522) terminou **BLOCKED, changed=false**: a pesquisa incluiu ficheiros de backups historicos; nao declarar pacote removido ou bytes libertados. Separar referencias a backups de consumidores operacionais antes de repetir qualquer remocao. Nao eliminar backups sem classificacao e prova de independencia.
- **Continua pendente:** reboot da VPS, restauro real de backups e certificacao de desinstalacao autonoma; aliases historicos identificados nas seccoes anteriores. As instalacoes de cada projeto permanecem sob a sua propria raiz, sem partilha de PM2 ativo.

## Verificacao complementar — 04-11-2026 (fonte GitHub, sem alteracao de runtime)

- **Runtimes Node.js dos dois robos:** as unidades versionadas `martaxi-boss/telegram-robot-leads/deploy/systemd/pm2-telegram-robot-leads.service` e `martaxi-boss/iptvpn-bot/deploy/systemd/pm2-iptvpn-bot.service` arrancam o PM2 privado do respetivo projeto com `/usr/bin/node`. Portanto, o **pacote, estado e daemon PM2 sao privados**, mas o **interpretador Node.js e fornecido pelo Ubuntu**. Se a regra exigir nao partilhar nem este runtime do sistema, a independencia absoluta continua por certificar: inventariar versao/binario e instalar um Node compativel por projeto, ajustar os `ExecStart/ExecReload/ExecStop` e scripts que o invocam, validar daemon, worker, boot e rollback, e so depois remover qualquer dependencia global obsoleta. Nao e prova de uma segunda instalacao fisica do projeto fora da raiz.
- **Alias de nome historico no Telegram Robot Leads:** `scripts/telegram-iptvpn-status.sh` esta versionado no proprio repo de Telegram Robot Leads e e apenas um wrapper que reencaminha para `scripts/telegram-robot-leads-status.sh`, devido ao antigo nome TELEGRAM-IPTVPN. Nao e um launcher do projeto independente `iptvpn-bot`; nao eliminar sem verificar quem ainda o invoca.
- **Integridade GitHub confirmada:** `martaxi-boss/telegram-robot-leads/scripts/activate_project_only.py` e `scripts/lead_health.py` referenciam o CLI PM2 interno; `martaxi-boss/iptvpn-bot/ecosystem.config.js` aponta para o seu `/srv/projects/iptvpn-bot`; os scripts antigos de arranque de multiplos projetos foram retirados da `main` deste ultimo repo. As verificacoes foram **apenas de fonte no GitHub**, nao um novo teste na VPS.

## Auditoria Ferrari da VPS e limpeza Hopper — 04-11-2026, apos 12:15 UTC

- **Inventario atual de leitura:** [Actions #41827728148](https://github.com/martaxi-boss/VPS/actions/runs/41827728148), resultado MCP `exit=0`. Em `/srv/projects`, **12 pastas fisicas** de instalacao e **um alias adicional** `codex-agent -> /srv/projects/Codex`. Os dois PM2 privados estao `active/enabled`; `pm2-root` permanece `inactive/not-found`; `/root/.pm2` inexistente. Os servicos `ssh`, `nginx`, `lowcost-europa` e `pink-vpn` estao ativos. Disco: 76 887 154 688 bytes totais e **16 302 669 824 bytes disponiveis**, 79% usado no instante da leitura.
- **PM2/Node globais:** `/usr/lib/node_modules/pm2` e o alias `/usr/bin/pm2` ainda existem. O Node do Ubuntu `/usr/bin/node` e v22.23.3; ambos os servicos privados PM2 ainda o invocam. Nenhuma alteracao ao Node ou ao pacote PM2 global foi efetuada.
- **Referencias a aliases:** [#41828056067](https://github.com/martaxi-boss/VPS/actions/runs/41828056067) e [#41828349440](https://github.com/martaxi-boss/VPS/actions/runs/41828349440) foram auditorias de leitura; as pesquisas amplas foram **truncadas pelos limites de ficheiros**, portanto nao provam ausencia geral de consumidores. A auditoria focada identificou **8 ficheiros de fonte operacional Low Cost** a mencionar `/etc/lowcost-europa` e **2 scripts do gateway PINK IPTV** a mencionar `/srv/pink-iptv`; conservar esses aliases ate atualizar e testar os respetivos consumidores. O alias Ferrari tambem consta em documentacao e bootstrap historicos. Nao confundir referencias historicas com consumo ativo.
- **Hopper — unica remocao desta etapa:** a primeira tentativa [#41828726641](https://github.com/martaxi-boss/VPS/actions/runs/41828726641) falhou antes de alterar o sistema por erro de iteracao. A repeticao corrigida [#41828910615](https://github.com/martaxi-boss/VPS/actions/runs/41828910615) terminou com `status=REMOVED,changed=true`: foi eliminado **somente o symlink** `/opt/hopper -> /srv/projects/hopper`, apos preflight sem consumidores nos 762 ficheiros verificados. A instalacao `/srv/projects/hopper/{bin,lib}` continua e os seis servicos verificados ficaram ativos. Nao alegar libertacao de espaco significativa pela remocao do link.
- **Proximo criterio de seguranca:** confirmar e atualizar os scripts que ainda usam aliases, verificar inicializacao apos reboot e restauro de backup por projeto, tratar o Node partilhado se a regra exigir binarios privados, e nao eliminar caminhos de dados, motores REA nem instalacoes sem prova de isolamento.
