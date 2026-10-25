# P229 - Recuperacao de Evidence P214 sem alterar politica de seguranca

## Estado
- Motor: original REA Linux VPS, 208 MCP; historico 116 certificados / 92 pendentes.
- P225: `close_binary` apagou os registos ativos (causa de codigo fortemente indicada).
- Copia P214: `/var/lib/rea-reversa/rea-p214-evidence-backup-7c5e1ad42fe74b121f3e2c4fe830c6c7.json`.
- Comprovada por GitHub Actions 40187442883 e 40187827609: 17.563 bytes, 6 Evidence, 0 Unknowns; SHA-256 `daa7bcc15a6cb1adf4fb46563100b2d67ff8b6694b191ef762d3cd2d8e61f3c4`.
- A autorizacao P228 assinou um caminho fora das raizes permitidas pela politica `8757abb589a779eaeda1d0eeefc85e4476503a41`. **Nao executar P228 nem alterar a politica para ultrapassar o bloqueio.**
- P229 conserva a politica, preserva a chave privada Ed25519 no Android e requer assinatura nova para o caminho do ficheiro temporario.

## Human Gate minimo: estagiar UMA copia restrita, na consola da VPS do proprietario
Este bloco **deve ser executado na VPS**, sob aprovacao explicita do proprietario. Nao executar em Termux Android ou no ChatGPT. Nao abre/fecha sessoes binarias nem reinicia servicos.

```bash
set -eu
SRC='/var/lib/rea-reversa/rea-p214-evidence-backup-7c5e1ad42fe74b121f3e2c4fe830c6c7.json'
DST='/opt/rea-reversa/rea/.rea-p229-restore-p214-7c5e1ad42fe74b121f3e2c4fe830c6c7.json'
EXPECTED='daa7bcc15a6cb1adf4fb46563100b2d67ff8b6694b191ef762d3cd2d8e61f3c4'
sudo test -f "$SRC"
sudo test ! -L "$SRC"
sudo test ! -e "$DST"
BEFORE="$(sudo sha256sum "$SRC" | cut -d ' ' -f 1)"
test "$BEFORE" = "$EXPECTED"
sudo install -T -o rea-reversa -g root -m 0600 "$SRC" "$DST"
AFTER="$(sudo sha256sum "$DST" | cut -d ' ' -f 1)"
test "$AFTER" = "$EXPECTED"
sudo -u rea-reversa test -r "$DST"
sudo stat -c 'PERMISSIONS=%a OWNER=%U GROUP=%G' "$DST"
printf 'REA_P229_STAGE=PASS SHA256=%s\n' "$AFTER"
```

Se falhar qualquer comando, nao autorizar importacao nem tentar compensar com chmod 777 ou alterar as politicas. O arquivo original P214 nao deve ser apagado ou movido. `sudo install` altera somente o destino temporario fixo dentro da raiz de analise ja permitida. O destino deve ser novo, de permissao 0600 e legivel apenas pela identidade REA.

## Assinatura Ed25519 do proprietario (Android Termux)
Apenas depois de `REA_P229_STAGE=PASS`, descarregar e executar o script offline existente:
`rea-linux/owner/sign_restore_p229_staged_evidence_android.py` no ramo `rea/one-skill-bridge-20261023`. Autorizar somente `import_evidence_bundle` com argumento `path=$DST`, usando `AUTORIZO_OPERACAO_SENSIVEL`. O script cria arquivo `rea-p229-restauro-<nonce>.json`, valida localmente assinatura Ed25519 e nao envia a chave PEM.

Enviar **so o JSON assinado** a esta conversa antes de expirar (45 min). O ChatGPT deve verificar esquema, nonce, prazo, hash dos argumentos, e usar somente `sealed_batch` cifrado pelo workflow original para o MCP original. O verificador Ed25519 na VPS continua obrigatorio e independente. Nao reutilizar a assinatura P228.

## Pos-execucao (somente se realmente suceder)
Confirmar o resultado real `import_evidence_bundle` com `isError=false` e seis Evidence recuperadas. Ler independentemente `get_evidence_bundle` e `list_unknowns`; esperar seis Evidence e zero Unknowns, sem reconstruir os registos posteriores P217/P218. Preservar SHA dos resultados e IDs. Nao executar `open_binary` ou `close_binary` enquanto a retencao de dados nao estiver corrigida. Guardar provas no incidente P225. Nao aumentar as 116 certificacoes historicas por uma recuperacao de registos.

Depois de readback PASS, apagar **apenas a copia estagiada** `$DST` na VPS, sob autorizacao do proprietario e depois de confirmar o arquivo original intacto; nunca apagar `$SRC`. Nao modificar outro projeto, workflow, plugin, skill, servidor, motor ou politica de autorizacao.
