# REA — registo legítimo do proprietário Ed25519

**Estado inicial de 24/10/2026:** o verificador `owner-approval-public.pem` ainda não estava instalado na VPS. O REA original e o seu catálogo de 208 ferramentas continuam preservados. O objetivo desta fase é registar a chave pública do proprietário para que cada operação sensível possa ser individualmente assinada. Isto **não** contorna licenças comerciais de fornecedores nem autoriza operações automaticamente.

## 1. Gerar o par no dispositivo do proprietário

**Android com Termux** (nunca na VPS, GitHub Actions ou num chat):

```sh
pkg install -y openssl
umask 077
mkdir -p "$HOME/.rea-owner"
if test -e "$HOME/.rea-owner/rea-owner-private.pem"; then echo 'JA EXISTE CHAVE PRIVADA: NAO SUBSTITUIR'; else
  openssl genpkey -algorithm ED25519 -out "$HOME/.rea-owner/rea-owner-private.pem"
  openssl pkey -in "$HOME/.rea-owner/rea-owner-private.pem" -pubout -out "$HOME/.rea-owner/rea-owner-public.pem"
fi
chmod 600 "$HOME/.rea-owner/rea-owner-private.pem" "$HOME/.rea-owner/rea-owner-public.pem"
openssl pkey -pubin -in "$HOME/.rea-owner/rea-owner-public.pem" -outform DER | sha256sum
cat "$HOME/.rea-owner/rea-owner-public.pem"
```

Enviar ao operador **apenas** o texto entre `BEGIN PUBLIC KEY` e `END PUBLIC KEY`, incluindo essas linhas, juntamente com o SHA-256 apresentado. Não enviar nunca `rea-owner-private.pem` nem fazer upload dela. Guardar cópia de segurança da chave privada num cofre próprio e protegido.

Alternativa em Windows/macOS/Linux: a cópia auditável do helper offline `owner_approval.py` do pacote da Skill admite `python owner_approval.py owner-keygen --dir DIRETORIO_LOCAL_PRIVADO`, após instalar `cryptography`. Imprimir e fornecer apenas `rea-owner-public.pem`; confirmar SHA-256 do DER público com OpenSSL (ou por um verificador equivalente).

## 2. Registo one-shot da chave pública

`provision_owner_verifier.py` é um helper opcional de inscrição **pública e explícita**, sem execução automática no GitHub Actions. Só pode ser executado na **VPS existente**, como utilizador SSH `ubuntu`, numa etapa separada sob controlo do proprietário:

```sh
python3 provision_owner_verifier.py \
  --public-key-file CAMINHO_DA_CHAVE_PUBLICA_PEM \
  --expected-sha256 SHA256_DER_CONFIRMADO_PELO_PROPRIETARIO \
  --approve-enrollment
```

O helper valida Ed25519, verifica o fingerprint, o proprietário e permissões da diretoria `~/.local/share/rea-chatgpt-trial/sealed-bridge`, e instala exclusivamente `owner-approval-public.pem` com `0600`. Não envia a chave privada para a VPS. Não substitui um verificador diferente, não reinicia serviços, não altera motores, fornecedores ou outros projetos. A assinatura de cada operação sensível continua obrigatória.

## 3. Verificação antes da certificação sensível

Confirmar por ação **somente de leitura** na ligação GitHub Actions → SSH → VPS que o fingerprint do verificador corresponde ao apresentado pelo proprietário; testar assinatura positiva e negativa sem executar efeito sensível. Registar run, commit e resultado. Só depois usar operações sensíveis reais com autorização específica, argumento-hash, prazo de expiração e nonce de uso único.

**Não existe autorização geral permanente por instalar a chave pública.** O proprietário continua a assinar caso a caso, com `owner_approval.py sign-step --approve-sensitive`. A chave pública de verificação não constitui licença para software de terceiros.
