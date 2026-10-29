# REA 6.8.0 original — Ponto 2: fornecedores existentes no Ubuntu (2026-10-29)

## Objetivo e ligação
Resolver, sem reinstalar nem modificar o REA original, os programas já presentes na VPS Ubuntu 24.04: Binwalk, Frida, Cutter, Chromium e Hopper. O pwntools 4.15.0 já foi resolvido no Ponto 1.

Todas as verificações usaram a ligação padrão GitHub Actions -> SSH com fingerprint Ed25519 validado -> utilizador ubuntu -> REA CLI standalone oficial.
Original fixado em `morluto/rea` tag `rea-agents-6.8.0`, commit `160d821ac9a0310afcb8d1fc427862dd6508add5`; hash de dois módulos compilados e lockfile verificados. Não foi usado o MCP antigo e não foram alterados projetos terceiros ou o código original.

## Resultado confirmado

| Componente | Estado após teste real | Ação / limite |
|---|---|---|
| **Binwalk** | **PASS** no REA original | Duas instalações detectadas: `/usr/bin/binwalk` antiga (interpreta `--version` como ficheiro e sai com 3) e **Binwalk 3.1.0** existente em `/opt/rea-reversa/providers/binwalk-3.1.0/bin/binwalk`. Selecionando `REA_BINWALK_COMMAND` por invocação, `rea inspect-firmware-regions` identificou **1 região** num ficheiro gzip controlado, sem alterar os bytes. Não reinstalado. |
| **Frida** | **PASS** em operação real | Além de descobrir dispositivos, o REA `instrument-with-frida` executou `spawn /usr/bin/sleep` controlado e uma mensagem JavaScript de teste, retornou saída normalizada e terminou com `cleanup_incomplete=false`. Não usou Android nem processos de terceiros. Node binding do REA já existia. |
| **Cutter 2.5.0** | **PENDENTE de sessão gráfica** | AppImage já instalado. `rea list-cutter-sessions --json` executou mas não encontrou sessão autenticada v2 utilizável; o ambiente SSH não possui `DISPLAY` ativo. Xvfb está instalado, mas não foi criada uma nova sessão gráfica nem instalado o plugin local de Cutter. Não classificar como operacional dentro do REA. |
| **Chromium/Playwright** | **INSTALADO, execução bloqueada pelo AppArmor Ubuntu** | Chrome for Testing `145.0.7632.6` é executável e não tem bibliotecas dinâmicas em falta (`ldd`). Um perfil de browser isolado arrancou e terminou com `SIGTRAP` antes de abrir CDP, com fatal `No usable sandbox!`. Ubuntu tem `apparmor_restrict_unprivileged_userns=1`. **Não desativar `--no-sandbox`, não alterar AppArmor sem ordem material, não abrir serviços permanentes**. Perfil/processo temporários removidos. A integração CDP do REA não pôde ser certificada neste host. |
| **Hopper** | **INSTALADO, mas rejeitado pelo REA** | `rea doctor --provider hopper --json` confirmou launcher e runtime de demo, mas `hopper-version` FAIL com `reason=unsupported_hopper_build`. O motor exige prova de integridade do pacote oficial; a versão existente não foi autenticada. O caminho de correção é uma atualização/reinstalação do demo oficial assinado após verificação da licença e efeito no sistema, não desativar a proteção nem forçar PASS. **Não atualizado nem usado**. |
| **pwntools** | **RESOLVIDO no Ponto 1** | Versão compatível 4.15.0 já isolada e aceite no ensaio real com pwndbg (`40937637409`), sem reinstalação aqui. |

## Provas GitHub Actions

- [Run 40938725218](https://github.com/martaxi-boss/VPS/actions/runs/40938725218) — `SUCCESS`: Binwalk real via CLI original, inventário Cutter, Chromium versão, Frida discovery, Hopper doctor, captura de 8 e 30 subprocessos, sem `cleanup_incomplete`.
- [Run 40939173526](https://github.com/martaxi-boss/VPS/actions/runs/40939173526) — `SUCCESS`: Frida instrumentação real com processo Linux próprio e diagnóstico detalhado Hopper `unsupported_hopper_build`.
- [Run 40939604107](https://github.com/martaxi-boss/VPS/actions/runs/40939604107) — `SUCCESS` do **ensaio controlado**, mas o Chromium **não conseguiu arrancar**; o browser saiu `-5`, com perfil removido. O sucesso do job não representa o sucesso do navegador.
- [Run 40939840752](https://github.com/martaxi-boss/VPS/actions/runs/40939840752) — `SUCCESS`: comprovação do erro fatal de sandbox, AppArmor ativado e ausência de bibliotecas `ldd` em falta; Cutter sem sessão.
- [Run 40940116245](https://github.com/martaxi-boss/VPS/actions/runs/40940116245) — `SUCCESS`: verificação final do workflow estável, Binwalk real novamente PASS, capturas 8 e 30 PASS, `cleanup_incomplete=0`.

## Estado deixado para uso futuro

**Binwalk 3.1.0:** selecionar a instalação já existente por ambiente **na invocação REA**, para não depender do `/usr/bin/binwalk` antigo e sem substituir binários:

```sh
REA_BINWALK_COMMAND=/opt/rea-reversa/providers/binwalk-3.1.0/bin/binwalk \
  /opt/rea-reversa/providers/node-v24.22.1/bin/node \
  /home/ubuntu/rea-original-upstream-680/scripts/rea.mjs \
  inspect-firmware-regions /caminho/para/firmware.bin --json
```

**Frida:** utilizar o binding Node já incluído no motor; a descoberta e a instrumentação local funcionaram. Não afirmar que um dispositivo Android remoto esteja ligado ou configurado.

**Cutter, Chromium, Hopper:** nenhuma tentativa de contornar segurança/licenças, nenhuma instalação ou serviço persistente. São **três condições não resolvidas** que exigem, respetivamente, sessão gráfica com bridge autenticada, ambiente Chromium com sandbox autorizado pela política do host, e pacote Hopper oficial autenticado compatível. Não misturar estes bloqueios com uma suposta falta de componentes das 229 ferramentas.

## Higienização

- Reutilizado o workflow existente `.github/workflows/rea-mcp-transport-20261027.yml` (nome legado, conteúdo CLI original); SSH, segredo, fingerprint e identidade intactos.
- Workflow final aponta de volta para o ensaio estável `rea-linux/tests/rea_original_existing_optional_suppliers_point2_20261029.py`, não para scripts de diagnóstico pontual.
- Não foram instalados programas nem alteradas permissões neste ponto.
- Chromium usou apenas um processo e perfil privado efémeros, eliminados após o ensaio; sem novo serviço, listener persistente, porta publicada, MCP ou coordenador.
- Evidência completa privada na VPS: `/home/ubuntu/rea-original-upstream-680-evidence/existing-suppliers-point2-20261029/`. Scripts no repo VPS sob `rea-linux/tests/`.

**Resultado do ponto 2:** Binwalk compatível localizado e testado, Frida funcional com prova dinâmica. Cutter, Chromium e Hopper permanecem pendentes por bloqueios reais que não devem ser removidos através de bypass de segurança ou licença. Verificações de processo continuam sem `cleanup_incomplete`.
