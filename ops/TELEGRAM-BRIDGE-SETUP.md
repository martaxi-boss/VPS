# ChatGPT + Telegram + Codex: ordens e relatórios

## Objetivo

Duas entradas para tarefas e um destino de notificação:

- **ChatGPT:** o proprietário pede uma auditoria e o assistente cria uma GitHub Issue do tipo `[codex audit]` no repositorio `martaxi-boss/VPS`.
- **Telegram:** o proprietário envia uma mensagem privada ao bot `/audit <tarefa>`, escreve `Codex, ...` **ou grava diretamente um áudio no Telegram** (sem teclado). O áudio é transcrito localmente numa execução isolada e encaminhado como **auditoria de leitura**, criando uma Issue e iniciando-a via `workflow_dispatch`.
- **Codex:** usa a conta ChatGPT já autenticada **no VPS**. Não é necessário copiar credenciais Codex para o GitHub nem usar uma API paga à parte.
- **Resposta:** o GitHub Actions comenta a Issue com o relatório e envia o resultado completo ao Telegram. Se for longo, o Telegram recebe um resumo e um ficheiro de texto com o relatório completo.
- **Consulta pelo ChatGPT:** o utilizador pode pedir a qualquer momento para consultar o resultado da Issue no GitHub.

O GitHub é a fonte de verdade para os relatórios. Não se tenta inserir mensagens diretamente numa conversa existente do ChatGPT.

## Como ativar (exige uma ação do proprietário)

1. No Telegram, abrir [@BotFather](https://t.me/BotFather), enviar `/newbot` e escolher o nome e o username do bot. **Não colocar o token em nenhuma mensagem do ChatGPT, Telegram do projeto ou GitHub Issue.**
2. Abrir o bot recém-criado e enviar `/start` para permitir que ele te escreva.
3. Identificar o ID numérico do teu chat privado Telegram. O ID pode ser consultado por uma ferramenta de identificação de Telegram ID à tua escolha, por exemplo `@userinfobot` (um bot de terceiros); não partilhar segredos.
4. Nas definições do GitHub do repositório VPS, em [Actions secrets](https://github.com/martaxi-boss/VPS/settings/secrets/actions), criar **dois secrets**:
   - `TELEGRAM_BOT_TOKEN`: token obtido no BotFather;
   - `TELEGRAM_CHAT_ID`: número do teu chat privado Telegram (apenas algarismos positivos).
5. Em GitHub → Actions → **Telegram commands to Codex**, executar uma vez **Run workflow** ou esperar até ao próximo disparo agendado. Enviar `/help` ao bot. Confirmar que o bot responde.
6. Teste real: `/audit Lê o README do repositório VPS e resume os objetivos sem alterar ficheiros.`. Deverás receber uma mensagem de tarefa aceite e, quando o Codex acabar, o relatório.

Não é necessário instalar software nem configurar serviços novos no VPS; a receção do Telegram é feita por GitHub Actions.

## Comandos do Telegram

- `/help` ou `/start`: instruções do bot.
- `/audit <pedido>` ou `/codex <pedido>`: nova auditoria Codex.
- `Codex, analisa ...`: forma em linguagem natural para uma auditoria.
- `🎙️ Áudio de voz` (até 90 segundos / 8 MB): grava normalmente pelo microfone do Telegram; **não precisas dizer Codex**, nem escrever texto. O bot envia o aviso de receção, faz a transcrição local para português e encaminha o pedido como **auditoria de leitura**. Uma resposta privada mostra o texto reconhecido e o número da tarefa. A primeira transcrição pode levar minutos para instalar o motor e obter o modelo no executor temporário. Não há chave de API paga para transcrição.
- `/status 123`: lê a última resposta Codex da Issue #123 no GitHub.
- `/fix`, `/cursor`, `/composer`, `/sonnet`: devolvem aviso de indisponibilidade, pois estes modos ainda não foram ativados.

O bot aceita ordens **apenas do ID numérico explicitamente autorizado**, em conversa privada, sem aceitar mensagens de grupos, outros utilizadores ou outros bots. As tarefas continuam em sandbox de leitura, sem deploy nem edição.

## Tempo e recursos

- A recolha de mensagens usa o `schedule` do GitHub Actions em intervalos de aproximadamente **cinco minutos**. O GitHub pode atrasar ou, em circunstâncias excecionais, não executar uma ocorrência; por isso **não é um chat instantâneo**. Em caso de espera excessiva, correr manualmente o workflow `Telegram commands to Codex` no separador Actions para recolher os áudios pendentes. O agendamento não tem SLA e será necessário um canal de webhook/long polling independente para interação verdadeiramente instantânea.
- Os resultados são enviados ao Telegram no próprio fim do trabalho Codex, sem esperar pelo ciclo seguinte.
- O poller não usa tokens do ChatGPT Work nem da conta Codex; apenas as auditorias de facto executadas pelo Codex consomem a utilização correspondente.
- Para um áudio, o executor de GitHub instala temporariamente `faster-whisper==1.2.1` num ambiente virtual **sem acesso às credenciais GitHub/Telegram/SSH** e descarrega um modelo `base` para processamento **local em CPU**. Áudio e cache são eliminados com o diretório temporário. Não há consumo da API de transcrição da OpenAI; há tempo de execução GitHub Actions e downloads temporários de dependências/modelo.
- A monitorização horária anteriormente configurada no ChatGPT deve ser desligada quando o Telegram estiver confirmado como principal canal, para não haver avisos duplicados.

## Privacidade

**O repositório `VPS` é público.** O texto das Issues, os relatórios de auditoria e os logs públicos do GitHub podem ser consultados por terceiros. Só colocar instruções apropriadas para um repositório público. Nunca enviar passwords, dados pessoais, tokens, chaves, segredos ou conteúdo confidencial. O bot rejeita alguns padrões evidentes de credenciais, mas esta proteção não é infalível.

Os **áudios nunca são anexados à Issue** e o modelo de voz executa sem segredos em ambiente isolado, mas **o texto transcrito e o relatório de auditoria são publicados na Issue do GitHub público**, tal como acontece com as ordens escritas. Evita dizer dados pessoais, credenciais, nomes privados ou outros conteúdos confidenciais no áudio. O filtro de segurança é apenas defensivo, não garante deteção de todos os segredos. O reconhecimento automático pode ouvir mal: confirma no Telegram a frase reconhecida e a Issue.

Os dois segredos Telegram devem permanecer apenas nos GitHub Actions secrets. Não os colocar em ficheiros, commits, screenshots ou mensagens ao ChatGPT. A execução avisa no log se faltar a configuração e, nesse caso, não envia mensagens.

## Preparação para Cursor

A arquitetura usa GitHub como fila e histórico e Telegram como interface. Pode ser estendida para Cursor/Composer/Sonnet quando existir uma autenticação/integração válida, sem mudar a maneira como o utilizador dá ordens.

**Estado atual:** Codex `audit` pronto; Codex `fix` e Cursor ainda não ativos. Não sugerir que trabalho de correção está a acontecer automaticamente antes de o validar.


## Separação de agentes e estado do serviço residente (proposta #84)

- «Boa tarde Codex» seleciona apenas Codex; uma saudação não dispara trabalho pago.
- «Boa tarde Gemini» identifica Gemini, mas não o executa enquanto a integração Gemini não existir. Nunca reenviar ao Codex pedidos dirigidos a Gemini.
- No serviço residente, a seleção é persistida e cada ordem recebida conserva o destinatário da receção, mesmo com áudios em fila.
- A implementação ainda depende de instalação e confirmação na VPS; enquanto isso, o workflow GitHub continua best-effort, sem garantia de resposta imediata.
- O serviço residente e o poller GitHub não podem consumir simultaneamente `getUpdates` do mesmo bot; a migração requer troca coordenada e prova em produção.
