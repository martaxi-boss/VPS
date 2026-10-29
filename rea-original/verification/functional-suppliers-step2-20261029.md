# REA original — Ponto 2: testes funcionais de fornecedores existentes (29-10-2026)

## Estado final: PASS, 11/11, cleanup_incomplete = 0

A execução final, corrigida e concluída com **SUCCESS**, foi
[GitHub Actions run 40929293048](https://github.com/martaxi-boss/VPS/actions/runs/40929293048)
(job 123643119983; commit de teste bc235f024f1b16bf8316ee2e61932768f2eeff3f).

O primeiro ensaio
[run 40928524124](https://github.com/martaxi-boss/VPS/actions/runs/40928524124)
já tinha concluído todas as chamadas reais com saída JSON válida e sem erro
de limpeza. Porém, um erro **no nosso validador de testes**, e não no Ghidra,
marcava a pesquisa de procedimentos como FAIL: o contrato oficial
\`search_procedures\` devolve uma **lista** em
\`normalized_result\`, e o validador incorretamente exigia um objeto com
\`matches\`. A correção no script validou entradas reais com nomes
e endereços, exigiu lista não vazia e não alterou nenhum ficheiro do motor original.

## Matriz de provas

| Cenário real | Resultado |
|---|---|
| Unblob 26.6.4 já instalado, executável e com versão correta | PASS |
| \`doctor --provider ghidra\` com JDK 21 já existente | PASS |
| \`doctor --provider jadx\` com JAR 0.7.1 já existente | PASS |
| Ghidra 12.1.4, \`analyze /usr/bin/true --provider ghidra\`, visão geral de ELF Linux real | PASS |
| Ghidra, pesquisa real de funções (\`search --kind procedures --mode regex\`) com entradas e endereços | PASS |
| JADX, \`inspect-android-package\` no APK público Appium ApiDemos 6.0.18 SHA-pinned | PASS |
| JADX, \`inspect-android-class\` em \`io.appium.android.apis.ApiDemos\` | PASS |
| JADX, \`inspect-android-method\` no \`onCreate\`, com corpo Java recuperado | PASS |
| Unblob, \`extract-firmware\` numa amostra real controlada gzip + USTAR, SHA-256 de ficheiro extraído validado | PASS |
| Captura de 8 subprocessos após testes dos fornecedores; grupo e diretório temporário limpos | PASS |
| Captura de 30 subprocessos após testes dos fornecedores; grupo e diretório temporário limpos | PASS |
| **Total** | **11 PASS / 0 FAIL** |

**Nenhuma** destas chamadas produziu \`cleanup_incomplete\`.

## Ambiente e isolamento

- Motor original oficial: \`morluto/rea\`, tag \`rea-agents-6.8.0\`, fonte exata \`160d821ac9a0310afcb8d1fc427862dd6508add5\`.
- Build e hashes de módulos críticos conferidos antes dos testes; versão e lockfile existentes sem divergências.
- Acesso: **GitHub Actions → SSH com host Ed25519 validado → utilizador ubuntu → CLI REA original**.
- Workflow existente: \`.github/workflows/rea-mcp-transport-20261027.yml\`, apesar do nome legado. **Não usa o MCP antigo.**
- Script: \`rea-linux/tests/rea_original_functional_suppliers_step2_20261029.py\`.
- **0 instalações de fornecedores**, **0 alterações aos serviços**, **0 alterações ao código original**, **0 novas portas MCP**, **0 modificações noutros projetos**.
- Fornecedores reutilizados da VPS:
  - Ghidra: \`/opt/rea-reversa/tools/ghidra_12.1.4_PUBLIC\`
  - JDK 21: \`/opt/rea-reversa/tools/jdk-21\`
  - JADX: \`/opt/rea-reversa/tools/jadx-headless-mcp-0.7.1-all.jar\`
  - Unblob: \`/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob\` (ACL de travessia \`ubuntu\` verificada anteriormente)
- APK de teste público, não um projeto do proprietário: \`ApiDemos-debug.apk\` de Appium 6.0.18; SHA-256 \`a9eecf37b26cd084855c530db81c2bb1b91f4c1b095a04f47aa7c20e2791f686\`. Foi obtido e validado no primeiro ensaio; reutilizado com verificação de digest no segundo.
- Evidência individual, resultados normalizados, stdout/stderr e sumário estão na VPS:
  \`/home/ubuntu/rea-original-upstream-680-evidence/functional-suppliers-step2-20261029/\`.

## Limites de interpretação

A prova demonstra **funcionamento real** de Ghidra, JADX e Unblob em operações específicas sobre entradas reais e limpeza verificada dos processos nos casos de 8 e 30 subprocessos. Não equivale à certificação de todas as operações do fornecedor, das 229 ferramentas de catálogo ou das 170 ferramentas anteriormente certificadas noutra instalação. Não elimina matematicamente uma falha intermitente nem identifica isoladamente a antiga ponte MCP como causa: o antigo serviço usava um processo persistente com identidade diferente, enquanto estes testes usam CLI por \`ubuntu\`.

**Ponto 2 concluído.** Não iniciar os pontos seguintes sem ordem do proprietário.
