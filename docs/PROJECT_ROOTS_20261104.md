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


## Lowcost Europa — rollout staging comprovado em 07-11-2026

- Repo da aplicação `martaxi-boss/lowcost-europa`, revisão pública `main` **`2d116175b71ec193a80ab0e71ac92217c7c6347e`**.
- VPS real em `/srv/projects/lowcost-europa` instalada nessa revisão pelo [run #42391168372](https://github.com/martaxi-boss/VPS/actions/runs/42391168372). O job confirmou `LOWCOST_BACKUPS_PREFLIGHT=PASS`, `LOWCOST_DEPLOYED_SHA=2d116175b71ec193a80ab0e71ac92217c7c6347e`, `LOWCOST_TRACKED_WORKTREE=CLEAN`, serviço e HTTP local PASS, HTTPS exterior e `noindex` PASS.
- A revisão anterior era `388860c6a167686a378b89f4282304bce89c25de`, com nove alterações locais versionadas. **Todas foram preservadas** num arquivo privado sob `/srv/projects/lowcost-europa/private/deploy-history/` antes do reset exato. O ficheiro local divergente `deploy/scripts/offsite-restore-drill.sh` nunca foi enviado ao GitHub público. A pasta privada e os backups não foram apagados. A cópia de rollback deve continuar preservada até futura verificação/retencão autorizada.
- A primeira tentativa [#42391005853](https://github.com/martaxi-boss/VPS/actions/runs/42391005853) detetou permissões insuficientes para recolher JS; `LOWCOST_ROLLBACK_STATUS=PASS`. A revisão corrigida [#42391168372](https://github.com/martaxi-boss/VPS/actions/runs/42391168372) passou após ajustar apenas leitura dos ficheiros-fonte públicos no próprio projeto.
- Browser real do domínio teste `https://lowcost-europa.duckdns.org`: [Chromium #41605911458, attempt 2](https://github.com/martaxi-boss/lowcost-europa/actions/runs/41605911458) **PASS: 15/15, 0 erros**, desktop 1440px e Android-emulado 390px, home/cinco categorias/pesquisa, sem overflow horizontal. Testou robots `Disallow: /`, header `noindex`, redirecionamento do painel de acesso anónimo e navegação/filtros/comparação; dados reais de ofertas não são garantia de stock ou prazo.
- Workflow temporário `.github/workflows/lowcost-one-shot-rollout-20261107.yml` foi **apagado** de `VPS/main` no commit `5548bfd2807b006ecc592603a75e595a074eeec4`. A execução foi por GitHub Actions→SSH preexistente, não uma ação Ferrari tipada. Não se criou daemons, coordenação na VPS, dependências globais ou ponte nova.
- Domínio comprado pelo Owner **ainda por configurar**. Não houve mudança DNS, certificado, Host, HSTS, dados legais, aprovação comercial ou indexação nesta intervenção. A independência total dos scripts de backup e a recuperação offsite ainda exigem teste de restauro numa operação específica; esta atualização só verificou o dump local e o marcador/estado de backups.


## Lowcost Europa — homepage Atelier visualmente diferenciada, publicada 07-11-2026

- A homepage anterior era tecnicamente nova, mas o proprietário não notou diferenças substanciais no DuckDNS. Foi realizada uma revisão visual distinta, com marfim/verde-escuro, tipografia editorial, CTA, pesquisa e categorias numa nova faixa. A aplicação, os dados reais e os links afiliados mantiveram-se; não foram inventados produtos.
- Código: [PR #199](https://github.com/martaxi-boss/lowcost-europa/pull/199), **MERGED**, revisão `lowcost-europa/main` **`6ff280ae6bb2e727166515f21c0803bad4d2e627`**. CI, auditoria e testes de Chromium sobre fonte passaram (incluindo 717 testes Django). Sem alterações de requisitos ou migrações de esquema.
- VPS: [run #42393181833](https://github.com/martaxi-boss/VPS/actions/runs/42393181833) **PASS**, verificou identidade SSH pinada, dumps e saúde de backup, permissões de leitura do código, Django check e makemigrations dry-run, collectstatic, reinício saudável e HTTP/HTTPS. `LOWCOST_DEPLOYED_SHA=6ff280ae6bb2e727166515f21c0803bad4d2e627` e `LOWCOST_TRACKED_WORKTREE=CLEAN`.
- O estado anterior `2d116175b71ec193a80ab0e71ac92217c7c6347e` e os estáticos de fallback foram conservados no arquivo privado sob `/srv/projects/lowcost-europa/private/deploy-history/`, com rollback preparado. Arquivos anteriores e o script de restauro divergente também permanecem resguardados; não apagar automaticamente.
- Inspeção real HTTPS no DuckDNS: [Chromium #41605911458, attempt 3](https://github.com/martaxi-boss/lowcost-europa/actions/runs/41605911458) **PASS, 15 verificações, 0 erros e 0 avisos**, home/cinco especialidades/pesquisa, desktop 1440 e móvel emulado 390, sem overflow horizontal; capturas completas ficaram no artefacto `lowcost-staging-browser-qa`.
- Verificações positivas de `noindex` no header/meta e `Disallow: /` em robots; não houve alteração de DNS/domínio pago, certificação do novo domínio, HSTS, dados do painel, publicação comercial nem indexação.
- Procedimento efémero `.github/workflows/lowcost-atelier-one-shot-20261107.yml` foi **eliminado** de `VPS/main` após êxito, commit `ade2ca6b533ad2a56b6f6cda81ab5eda806cbac5`. O deploy foi via GitHub Actions→SSH já autorizado, não uma execução `kind=` do Ferrari, nem criação de outro coordenador.
- As fotografias de fornecedores continuam de origem externa; a aprovação visual humana, a qualidade real dos fornecedores e o restauro offsite completo não são garantidos pelos testes automatizados.


## Lowcost Europa — linguagens do navegador (estado ATUAL, 07-11-2026)

- **Reversão visual pedida pelo proprietário foi respeitada.** A homepage Atelier de PR #199 foi retirada do site real e da árvore de código: GitHub `52a1de3a8386a52178eea492e8d41eaaba54b437` tem árvore exatamente igual à antiga revisão pré-Atelier `2d116175b71ec193a80ab0e71ac92217c7c6347e`. VPS restaurada em [run #42394698529](https://github.com/martaxi-boss/VPS/actions/runs/42394698529), com layout original, navegação e cinco categorias. A secção histórica Atelier acima não deve ser confundida com o estado ativo.
- **Implementação multilíngue limitada à apresentação:** PR [#200](https://github.com/martaxi-boss/lowcost-europa/pull/200) e correção de cache CSS PR [#201](https://github.com/martaxi-boss/lowcost-europa/pull/201), integrados no commit `lowcost-europa/main` **`c00376d0b9c069abed3908933cc15502c8bafa10`**. Cinco línguas PT-PT, ES, EN, FR, DE: `Accept-Language` como preferência inicial; formulário Django de troca manual com cookie funcional seguro; fallback PT-PT. Não usa localização por IP, fornecedores de tradução, cookies de analytics ou novos serviços. Conserva IDs, links, catálogo, paginação, owner panel, CSS de layout original e todas as cinco categorias.
- **Teste de código** CI [#42401421702](https://github.com/martaxi-boss/lowcost-europa/actions/runs/42401421702) PASS, **teste de interface** [#42401421828](https://github.com/martaxi-boss/lowcost-europa/actions/runs/42401421828) PASS: 18 casos Chromium incluindo os cinco idiomas, persistência do idioma manual, quatro larguras de ecrã e cartões/filtros/comparação.
- **Atualização da VPS** [#42401824870](https://github.com/martaxi-boss/VPS/actions/runs/42401824870) **PASS**, incluindo chave SSH pinada, procedimento SHA-256 verificado, saúde de backups, ausência de migrations e dependências novas, Django check, `collectstatic`, reinício, resposta HTTP local e HTTPS externo com `noindex`. Prova `LOWCOST_LANGUAGE_pt-pt=PASS`, `_es=PASS`, `_en=PASS`, `_fr=PASS`, `_de=PASS`; `LOWCOST_DEPLOYED_SHA=c00376d0b9c069abed3908933cc15502c8bafa10`; worktree limpo. Código da versão anterior e estáticos ficaram preservados no arquivo **privado** `/srv/projects/lowcost-europa/private/deploy-history/` para rollback; não eliminar automaticamente.
- **Site publicado no DuckDNS testado novamente:** [Chromium #41605911458 tentativa 5](https://github.com/martaxi-boss/lowcost-europa/actions/runs/41605911458): **15/15 PASS, 0 erros** em desktop e emulação móvel; cinco categorias e navegação preservadas, sem overflow horizontal. Conteúdo do vendedor e títulos das ofertas não são traduzidos automaticamente para evitar adulterar dados comerciais.
- Workflow efémero `.github/workflows/lowcost-five-language-rollout-20261107.yml` foi **apagado** de `VPS/main` no commit `567a76da423a278a74a04e0e5dba2f28dab49d61`. Instalação via GitHub Actions→SSH autorizado, **não** um job tipado Ferrari `kind=operation`. Não houve alterações ao DNS, domínio pago, Nginx, certificado existente, base de dados, pagamentos, indexação comercial nem serviços de terceiros. Dados de logística, vendedor e entrega europeia continuam sujeitos a confirmação no parceiro.
