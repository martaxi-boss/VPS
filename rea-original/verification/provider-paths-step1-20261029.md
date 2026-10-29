# REA original — Ponto 1: localizar fornecedores existentes (29 outubro 2026)

**Resultado:** descoberta dos caminhos concluída. **Ghidra e JADX: diagnóstico oficial PASS. Unblob: instalado mas bloqueado por permissões do utilizador ubuntu.**

## Teste real e arquitetura

- GitHub Actions: https://github.com/martaxi-boss/VPS/actions/runs/40925694721 — **SUCCESS**
- Execução anterior da localização sem JDK 21 selecionado: https://github.com/martaxi-boss/VPS/actions/runs/40925415253 — SUCCESS como diagnóstico de caminhos; Ghidra doctor não estava pronto com Java 17.
- A instalação original é `morluto/rea` `rea-agents-6.8.0` no commit `160d821ac9a0310afcb8d1fc427862dd6508add5`.
- Caminho de execução: **GitHub Actions → SSH com chave do host verificada → ubuntu → REA original CLI**.
- Script utilizado: `rea-linux/tests/rea_original_existing_provider_paths_20261029.py`.
- Evidência detalhada: `/home/ubuntu/rea-original-upstream-680-evidence/provider-paths-20261029/summary.json`, `doctor-ghidra.json` e `doctor-jadx.json`.
- Nenhum fornecedor/pacote novo instalado na VPS, nenhum código do REA alterado, nenhum MCP antigo chamado, nenhum serviço iniciado/reiniciado, nenhuma permissão alterada.

## Caminhos verificados em leitura

| Componente | Caminho selecionado | Resultado |
|---|---|---|
| **Ghidra 12.1.4** | `/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC` | Ghidra metadata e analyzeHeadless acessíveis; `rea doctor --provider ghidra --json` **PASS, rc=0** |
| **JDK 21** | `/opt/rea-reversa/tools/jdk-21` | Java e javac acessíveis, versão 21; cumpre mínimo de Ghidra |
| **JADX headless MCP 0.7.1 JAR** | `/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar` | JAR acessível, contém classes oficiais requeridas; `rea doctor --provider jadx --json` **PASS, rc=0** |
| **Unblob 26.6.4** | `/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob` | Detectado no inventário; `ubuntu` **não consegue atravessar** o diretório `/opt/rea-reversa/providers/unblob-26.6.4` |
| **Primeiro bloqueio Unblob** | `/opt/rea-reversa/providers/unblob-26.6.4` | permissões **0750**, proprietário UID **994**; nenhuma alteração aplicada |

Outras cópias acessíveis foram observadas:
- Ghidra: `/home/ubuntu/.local/share/rea-chatgpt-trial/tools/ghidra_12.1.4_PUBLIC`.
- JADX: `/home/ubuntu/.local/share/rea-chatgpt-trial/tools/jadx-headless-mcp-0.7.1-all.jar`.
- JDK 21: `/home/ubuntu/.local/share/rea-chatgpt-trial/tools/jdk-21`.

O sistema também contém JDK 17 (`/usr/lib/jvm/java-17-openjdk-amd64`), **não adequado** ao Ghidra 12.1.4. O erro anterior de Ghidra não prova incompatibilidade do fornecedor; desapareceu no diagnóstico ao selecionar o JDK 21 existente.

## Configuração por invocação para o REA original (não aplicada persistentemente)

```sh
export GHIDRA_INSTALL_DIR=/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC
export JAVA_HOME=/opt/rea-reversa/tools/jdk-21
export REA_JADX_MCP_JAR=/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar
```

Estas três variáveis foram usadas **somente no ambiente isolado do teste**. Não foram gravadas no motor original nem na configuração do serviço antigo. Os futuros testes GitHub Actions podem passá-las ao invocar o CLI original.

## Condição de fecho do ponto 1

- **Localização dos três fornecedores:** concluída.
- **Ghidra e JADX preparados para testes funcionais do ponto 2:** sim, mediante variáveis de ambiente por invocação.
- **Unblob acessível ao ubuntu:** **não**; não confundir ausência de acesso com incompatibilidade ou ausência de instalação.
- **Próxima ação eventual:** resolver legitimamente o acesso ao Unblob, sem alterar a propriedade ou permissões de instalações alheias sem controlo de impacto. Até lá excluir operações que exigem Unblob.
- **Conclusão geral:** dois diagnósticos oficiais PASS; zero instalações e zero mudanças no REA original. Uma restrição de permissão permanece aberta.
