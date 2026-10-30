# REA FINAL - instalacao autonoma e transporte substituivel

Este arranque pertence a instalacao do REA FINAL, nao a GitHub Actions,
SSH, Desktop Commander ou ChatGPT. O motor do autor permanece inalterado.

## Layout Linux x64

    ~/rea-original-upstream-680/           # motor original rea-agents 6.8.0
    ~/rea-final-runtime/                   # runtime isolado e fornecedores
      bin/rea-mcp                          # copia de rea-linux/runtime/rea-mcp
      vendors/                             # fornecedores do runtime

Para instalar ou atualizar apenas o arranque, a partir de uma copia do repositorio:

    install -D -m 755 rea-linux/runtime/rea-mcp "$HOME/rea-final-runtime/bin/rea-mcp"

O repositorio guarda o arranque e estas instrucoes. As dependencias dos
fornecedores residem no runtime proprio da maquina, nunca na ponte. Numa
migracao, copiar ou reinstalar as dependencias compativeis com o novo sistema
e validar os respetivos executaveis, licencas, dados e backups. Nao incluir
segredos em commits.

Para alojar o motor noutro caminho, definir REA_FINAL_ENGINE_DIR no ambiente
do host. O runtime deduz-se da localizacao de bin/rea-mcp.

## Utilizacao sem GitHub nem SSH

    "$HOME/rea-final-runtime/bin/rea-mcp"

O processo comunica pelo MCP nativo em stdin/stdout. Um cliente MCP local
pode iniciar diretamente este comando. Pode-se testar usando initialize e
tools/list atraves de um cliente MCP, sem alterar o motor original.

## Fronteiras

- REA instalado: fornecedores, dependencias, caminhos e execucao MCP.
- ChatGPT e Skill: escolha das ferramentas no catalogo real e leitura de Evidence.
- GitHub Actions, SSH ou Desktop Commander: encaminhar pedidos e respostas.
- capture_process_scenario: sucesso do MCP confirma a captura; verificar
  separadamente normalized_result.exit.code, settlement e cleanup.

Nunca guardar instrucao de projeto, regras de fornecedores, caminhos internos
ou validacao de tarefas no transporte SSH.
