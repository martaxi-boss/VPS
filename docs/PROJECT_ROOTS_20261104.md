# VPS Ubuntu — mapa de instalacoes por pasta principal

**Verificacao real:** 04-11-2026, 01:20 UTC, motor Ferrari/REA atraves do GitHub Actions [#41753274718](https://github.com/martaxi-boss/VPS/actions/runs/41753274718). Este documento regista a situacao verificada, nao declara certificacao de desinstalacao.

## Regra vinculativa

Cada repositorio GitHub implantado tem raiz fisica unica em `/srv/projects/<nome-do-repositorio>/`. Uma ferramenta autonoma sem repositorio pode ter raiz propria em `/srv/projects/<nome-da-ferramenta>/`. Codigo, fornecedores, dependencias proprias, dados, backups, logs e segredos ficam internos. **Nunca partilhar instalacoes privadas entre projetos.** Servicos e configuracoes exigidos por Ubuntu (systemd, Nginx, APT, rede, PostgreSQL quando servidor do sistema) sao integracoes externas obrigatoriamente inventariadas, nao outra instalacao da aplicacao.

## Diretorios fisicos presentes

| Pasta fisica em `/srv/projects/` | Origem/proprietario | Componentes integrados | Pendente antes da desinstalacao autonoma |
| --- | --- | --- | --- |
| `telegram-robot-leads/` | `martaxi-boss/telegram-robot-leads` | Codigo, `.venv`, `data`, `private`, arquivo antigo | PM2 ainda partilhado; links e arranque automatico |
| `iptvpn-bot/` | `martaxi-boss/iptvpn-bot` | Codigo, `.venv`, `config`, `private` | PM2 global usa `/root/iptvpn_bot/start.sh`; aliases historicos |
| `pink-iptv/` | `martaxi-boss/pink-iptv` | Backend, testes/dispositivo, dependencias proprias | Certificar restart, VPN/Android e aliases |
| `lowcost-europa/` | `martaxi-boss/lowcost-europa` | Codigo, `.venv`, `data`, `private`, `www`, backups de configuracao | Eliminar aliases remanescentes apos validar todos os consumidores e restart |
| `fadego/` | `martaxi-boss/fadego` | Releases, `current`, dependencias, `www/preview`, backup Nginx | Certificar restart, DB/backups e alias `/srv/fadego-staging` |
| `skill-universal/` | `martaxi-boss/skill-universal` (Ferrari) | Motor, releases, ambientes, ferramentas, fornecedores privados | Validar consumidores do alias e apt global |
| `Engenheira-reversa/` | `martaxi-boss/Engenheira-reversa` (Trial) | Instalacao Trial isolada | A instalacao REA FINAL ainda esta externa; nao fundir motores |
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

## Instalacoes fisicas externas: nao confundir nem apagar

A auditoria #41753274718 observou os seguintes caminhos fisicos externos ainda existentes. `/etc/lowcost-europa` foi convertido posteriormente em alias na execucao #41753483523.

| Caminho externo | Identificacao | Estado |
| --- | --- | --- |
| `/home/ubuntu/rea-original-upstream-680` | **Codigo-fonte do REA FINAL**, pacote original do autor versao 6.8.0 | **PENDENTE** de migracao; nao apagar como se fosse legado |
| `/home/ubuntu/rea-final-runtime` | Dependencias/fornecedores do REA FINAL | **PENDENTE**, nao misturar com Trial nem Ferrari |
| `/home/ubuntu/rea-original-upstream-680-evidence` | Evidencias do REA FINAL | **PENDENTE**, proteger as provas |
| `/root/.pm2` | Daemon PM2 partilhado pelos dois robos Telegram | **PENDENTE** separar daemons e unidades systemd, sem duplicar processos |

O REA FINAL original tem numero de pacote 6.8.0. **Nao e prova de uma instalacao legacy inutil**: o README atual de `Engenheira-reversa` identifica esse checkout como motor FINAL. O proprio repo `Engenheira-reversa` e o Trial nao podem ser fundidos silenciosamente.

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
