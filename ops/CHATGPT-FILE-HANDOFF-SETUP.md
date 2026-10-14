# ChatGPT -> Coordenador: entrega privada de anexos selecionados

**Estado: backend + roteamento preparados; plugin ChatGPT ainda não ligado nem certificado em produção.**

A entrada pelo ChatGPT é opt-in: somente quando o Owner pedir. Ordens só de texto usam a Issue Owner normal, sem alterar o contrato anterior.

## Contrato de transporte

O ChatGPT suporta parâmetros de ficheiros em ferramentas MCP com `_meta["openai/fileParams"]`. O exemplo verificável está em `ops/chatgpt_coordinator_file_tool.json` e aceita `files: OpenAIFile[]`, sendo `download_url` e `file_id` obrigatórios, com nome/MIME opcionais. Este contrato é **um descritor**, não instala um plugin nem cria um serviço.

Uma futura ligação privada e autenticada (OAuth: confirmar de forma independente que a conta ligada pertence a `martaxi-boss`) deve chamar `ops.chatgpt_attachment_ingress.stage(files, inbox, verified_owner=...)`. A credencial OAuth do servidor não é um argumento que o modelo possa inventar. A ligação tem de receber apenas a seleção explicitamente autorizada, não todos os documentos da conversa.

**ATENÇÃO:** os URLs de download são credenciais temporárias; não podem aparecer em Issues, relatórios, logs, repositórios, outputs ou Telegram. Os hosts exatos devem ser validados e incluídos numa allowlist de confiança, configurada por quem instala o plugin; hosts desconhecidos falham sem transferência. Redirecionamentos HTTP são recusados. O backend conserva os originais, limita quantidade/tamanho e entrega SHA-256 e identificador aleatório de 128 bits.

## Entrega ao Coordenador existente

Depois de `stage` devolver e verificar a receção, e apenas mediante a ordem do Owner, criar Issue autenticada no repositório `martaxi-boss/VPS`:

```
Título: [coordinator run] <objetivo autorizado>
Corpo:
TARGET_REPOSITORY=martaxi-boss/<repositorio>
COORDINATOR_ATTACHMENTS_ID=<32 caracteres hexadecimais>
<ordem exata escolhida pelo Owner>
```

Apenas o identificador de um bundle privado entra na Issue pública, **não** os ficheiros nem links temporários. O workflow autentica o Owner, valida o identificador e passa-o à mesma execução do Coordenador. A execução no VPS consome o bundle uma única vez e confere a integridade antes de chamar o modelo; em falha, não avança para trabalhadores.

Para enviar uma ordem **sem documentos**, não escrever `COORDINATOR_ATTACHMENTS_ID`; usar o fluxo textual já certificado.

## Operações e segurança que ainda faltam

1. Alojar e ligar a ferramenta MCP por HTTPS com autenticação OAuth e autorização do Owner, aproveitando a VPS existente; não criar segundo Coordenador.
2. A ligação deve expor o descritor em `tools/list` e receber `tools/call` para `stage_selected_owner_files` com valores reais `fileParams`.
3. Disponibilizar a pasta privada `$HOME/codex-bridge/.coordinator-inbox` (0700, utilizador ubuntu). Nunca alterar permissões de uma pasta existente que não cumpra o contrato.
4. Verificar o host real dos URLs temporários de ChatGPT e ajustar a allowlist do backend, sem admitir redirects, hosts arbitrários ou IPs internos.
5. Fazer teste real de duas seleções (JPG e MP4), comparar SHA-256, comprovar que o **mesmo Coordenador Codex** recebeu e analisou os anexos, e repetir uma ordem só de texto. Só depois classificar `DELIVERY_VERIFIED`.
6. Definir retenção/limpeza de bundles privados nunca consumidos, sem deixar documentos eternamente na VPS.

Referência oficial (outubro de 2026): https://developers.openai.com/plugins/reference#file-apis

**Não indicar ao Owner que uma fotografia ou vídeo chegou ao Coordenador sem comprovativo de receção.**
