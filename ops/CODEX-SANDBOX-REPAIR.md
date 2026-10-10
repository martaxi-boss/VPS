# Reparacao controlada do sandbox Codex (Ubuntu 24.04)

Este repositório tem uma ligação do ChatGPT ao Codex CLI autenticado no VPS através do GitHub Actions. A leitura de ficheiros do repositorio era bloqueada pela restrição de namespaces/AppArmor do Ubuntu 24.04.

## Como funciona

O workflow `.github/workflows/codex-sandbox-repair.yml` aceita apenas Issues criadas pelo proprietário do repositório, com um destes títulos exatos:

- `[codex sandbox] inspect`: verifica Ubuntu, estado de AppArmor e tentativa de execução do bubblewrap sem alterações ao VPS.
- `[codex sandbox] apply`: instala apenas pacotes oficiais Ubuntu (`bubblewrap`, `apparmor-profiles`, `apparmor-utils`), testa o sistema; se ainda falhar, e somente se não existir perfil concorrente, instala/carrega o perfil oficial `bwrap-userns-restrict`.

Usa o segredo `VPS_SSH_PASSWORD` já configurado, sem aceder às credenciais de autenticação Codex no GitHub.

## Segurança e reversão

- **Nunca** altera `kernel.apparmor_restrict_unprivileged_userns`, não desativa perfis existentes e não reinicia serviços.
- Antes de criar um perfil, verifica se já existe um alvo `/etc/apparmor.d/bwrap-userns-restrict` ou outro perfil carregado potencialmente concorrente.
- Em caso de falha ao carregar ou testar um perfil que o script acabou de criar, remove somente esse perfil.
- A instalação de pacotes oficiais não é automaticamente revertida: esses pacotes podem permanecer instalados.
- A operação é limitada a preparar o sandbox do Codex CLI; não modifica ficheiros de produção, código da aplicação, nem dispara deploy.
- Os resultados publicados na Issue contêm só indicadores de configuração (sem logs completos do VPS).

## Validação funcional

Depois de instalar, iniciar uma nova Issue `[codex audit]` para ler efetivamente o README em ambiente `--sandbox read-only`. É esta auditoria, e não só o teste `bwrap`, que comprova o funcionamento completo.

Referência oficial OpenAI: https://developers.openai.com/codex/concepts/sandboxing
