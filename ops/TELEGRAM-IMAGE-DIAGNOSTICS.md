# Fotografias de erros da aplicacao -> Codex (Telegram privado)

## Objetivo

O proprietario pode tirar um print screen de um erro de IPTV, um menu, uma janela ou uma mensagem de falha e enviar **a imagem original ao bot Telegram**. Uma legenda e opcional, por exemplo:

> [imagem PNG] Corrige este erro de reproduçao. A janela nao abre quando inicio um filme.

Para ja, o Codex realiza um **diagnostico visual em modo read-only**, com relatorio privado ao Telegram. O suporte a correcoes de codigo e a outros agentes depende de ligar o repositorio **da aplicacao certa**, com revisao humana de pull requests; o atual executor clona so `martaxi-boss/VPS`, pelo que nao deve prometer que corrigira o codigo IPTV.

## Percurso da imagem

1. Telegram recebe uma foto (JPG gerado pelo Telegram), ou ficheiro PNG, JPG ou WEBP, com maximo 10 MB, num **chat privado explicitamente autorizado**.
2. Gateway valida o tamanho/MIME e cria uma Issue no GitHub com a descricao textual e **hash do identificador da imagem**, nunca com a imagem ou o identificador completo.
3. GitHub Actions verifica que a imagem corresponde a uma Issue criada pelo proprio gateway. So depois descarrega o ficheiro via Telegram Bot API, para uma pasta temporaria do runner.
4. GitHub Actions transmite a imagem diretamente por SSH para uma pasta temporaria do VPS. A transferencia e privada; **nao se faz commit, anexo a Issue, upload de artefacto, nem URL publico da fotografia**.
5. Codex CLI recebe a imagem original na opcao `--image` e o texto da ordem pela entrada padrao, usando sandbox `read-only`.
6. A imagem e apagada no VPS no fim do runner, mesmo que a auditoria falhe. Um passo adicional tenta remover imagens pendentes se a conexao falhar.
7. Os relatorios associados a imagens nao sao publicados nos comentarios ou artefactos publicos. O relatorio completo segue para o chat privado Telegram, como mensagem ou ficheiro.

## ChatGPT

No ChatGPT, o proprietario ja pode enviar diretamente capturas: o assistente ve a imagem e pode explicar o problema. A integracao GitHub conectada nao transfere, por si so, os bytes do anexo desta conversa ate ao Codex CLI. Para o **mesmo ficheiro ser visto pelo Codex no VPS**, enviar o print pelo Telegram ao bot (quando ativado).

Quando houver ligacao Cursor/Composer/Sonnet, este mesmo transporte privado pode ser adaptado ao agente de destino, desde que o respetivo ambiente suporte imagens.

## Configuracao e limites

O gateway e o workflow ja precisam dos GitHub Actions Secrets `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID`; o utilizador ainda precisa de criar/configurar o seu bot em @BotFather. Nunca pedir o token em mensagens do ChatGPT.

Um print pode conter dados pessoais, nomes de utilizadores ou chaves. Recomenda-se ocultar dados sensiveis antes de enviar. A **legenda** textual e colocada na Issue GitHub publica: nunca colocar dados confidenciais na legenda.

O gateway aceita apenas uma imagem por mensagem e ignora mensagens de grupos/ids nao autorizados. Videos, PDFs, albuns e multiplas imagens na mesma ordem ainda nao foram implementados.

## Validacao

Testes offline: mime e tamanho, autorizacao de chat, fotografia sem legenda, hash publico sem identificador privado, descarregamento PNG e permissoes dos ficheiros.

**Nao declarar que esta funcionalidade esta ativa ate um teste real com o bot pessoal estar concluido**. O fluxo de texto Codex anterior foi comprovado, mas a nova funcionalidade de imagens precisa de validacao end-to-end apos instalar os dois secrets.

