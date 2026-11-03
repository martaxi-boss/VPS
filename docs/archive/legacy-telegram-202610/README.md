# Arquivo historico Telegram Robot Leads — outubro de 2026

Estes cinco ficheiros foram retirados dos caminhos executaveis do repositório `martaxi-boss/VPS` e guardados aqui para consulta historica. Sao instaladores, workflows e um ativador com versoes e caminhos antigos, nao o processo Telegram Robot Leads atual.

**Desativacao real no Ubuntu:** o temporizador `telegram-leads-activate-20261020.timer`, ativo mas expirado desde 20-10-2026, foi desativado e os seus tres ficheiros (script e unidades systemd) foram movidos para `/srv/projects/telegram-robot-leads/archive/legacy/20261020-activation`. Prova [REA #41723648731](https://github.com/martaxi-boss/VPS/actions/runs/41723648731), codigo interno zero.

**Instalacao atual:** `/srv/projects/telegram-robot-leads`, com `data/` e `private/` fisicos, duas sessoes validadas por hash; commit GitHub do projeto `1e8c4e024cc3`. O PM2 continua online, mas o daemon global e uma pendencia de isolamento; nao confundir com `iptvpn-bot` nem com o Supervisor passivo.

Motivo do arquivo: estes workflows foram criados com SHAs e paths de 19–20 de outubro; o workflow de deploy historico ainda utilizava `/opt/telegram-robot-leads`. Reexecuta-los poderia provocar falhas ou reposicao de instalacoes obsoletas. A operacao historica fica preservada como texto; nenhum workflow arquivado e executado pelo GitHub Actions. A ponte do REA, o Supervisor e os outros workflows nao foram alterados.

Para futuras implantacoes, usar os scripts e testes atuais do repo `martaxi-boss/telegram-robot-leads` e verificar os caminhos antes de qualquer deploy. Nao reativar estes workflows expirados.
