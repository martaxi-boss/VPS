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

## Adenda de encerramento — recuperação Cutter e limites Chromium/Hopper (2026-10-29)

Esta adenda atualiza o resultado anterior sem apagar a evidência original. As verificações foram executadas exclusivamente pelo workflow existente, GitHub Actions -> SSH Ed25519 fixado -> ubuntu -> `/home/ubuntu/rea-original-upstream-680/scripts/rea.mjs`, no commit original `160d821ac9a0310afcb8d1fc427862dd6508add5`. Não foi utilizado o MCP antigo, nem Codex, nem alterado código do REA.

### Cutter 2.5.0 — PASS funcional em sessão gráfica isolada, sem serviço permanente

A primeira leitura do resultado de `list-cutter-sessions` no script de ensaio foi incorreta: o CLI devolve `sessions` e `discovery_status` diretamente, e não dentro de `normalized_result`. A leitura real confirmou `sessions_found` e uma sessão bridge v2 autenticada. O primeiro `cutter-command ... ij` terminou com `unreadable_output` porque o Cutter não confirmava a execução pela interface gráfica; a análise concluiu que a janela de opções de abertura do ficheiro bloqueava o dispatcher de UI.

A correção usou uma opção **oficial do Cutter 2.5.0**: iniciar a AppImage com `-A 0 /usr/bin/true` dentro de Xvfb, para abrir o ficheiro local e evitar a janela de análise inicial. A mesma sessão já instalada carregou temporariamente o plugin Python **já distribuído pelo REA original** `bridge/cutter/rea_bridge.py` através de um ambiente HOME/XDG privado e diretório `REA_CUTTER_BRIDGE_DIR` privado. O script não copia nem modifica o plugin e não deixa nenhum serviço permanentemente ativo.

**Ensaio real PASS**: o REA original descobriu **uma sessão autenticada** `discovery_status=sessions_found`; o comando real `cutter-command <session_id> <document_generation> ij --json-output` terminou com `rc=0`, saída de inspeção real do binário, `cleanup_incomplete=false`; a sessão Xvfb foi terminada e o HOME temporário removido. [Run 40944577193](https://github.com/martaxi-boss/VPS/actions/runs/40944577193) e evidência privada na VPS em `/home/ubuntu/rea-original-upstream-680-evidence/existing-suppliers-point2-20261029/targeted-followup/summary.json`.

**Operação futura:** o Cutter está disponível **sob demanda enquanto existir uma sessão gráfica e bridge v2 inicializadas no mesmo contexto de utilizador**. A descoberta de zero sessões no ensaio sem GUI posterior é esperada, não invalida o PASS funcional anterior. O REA não mantém sessões abertas permanentemente.

### Chromium/Playwright — bloqueio de política de segurança, não falta de binário

O Chrome for Testing 145.0.7632.6 existente arranca sem dependências dinâmicas em falta, mas não abre CDP na VPS. O kernel mantém `apparmor_restrict_unprivileged_userns=1`, `unprivileged_userns_clone=1`; a versão Playwright existente não dispõe de um auxiliar setuid `chrome-sandbox` válido e não foi localizada instalação Chromium/Chrome alternativa. Foi identificado um perfil `/etc/apparmor.d/chrome`, mas não foi demonstrado que conceda ao executável Chrome for Testing específico a autorização seletiva de user namespaces.

A solução tecnicamente suportada é **avaliar um perfil AppArmor dedicado ao caminho e identidade do Chromium fornecido**, com permissões limitadas ao necessário para o sandbox do navegador. Isto é uma **alteração material de política de segurança** e não foi executada. Mantidos `No usable sandbox!` e **Chromium CDP ainda NÃO CERTIFICADO**, sem `--no-sandbox`, sem desativar AppArmor global, sem alteração root e sem perfil CDP/porta persistente.

### Hopper — pacote instalado 6.6.0, catálogo oficial demo 6.6.1

`dpkg-query` identifica o pacote existente `hopper` versão **6.6.0**, com launcher `/opt/hopper/bin/Hopper`. O catálogo público do fabricante consultado pelo endereço presente no REA original anunciou a demo Linux Debian/Ubuntu **6.6.1**. O SHA-256 do launcher instalado não coincide com `main_exe_hash` da oferta corrente. `rea doctor --provider hopper --json` já tinha devolvido `unsupported_hopper_build`; o ambiente de demonstração está acessível, mas o executor não é autenticado pelo mecanismo atual de versão. Isso **não demonstra que o pacote antigo seja adulterado**.

Uma recuperação legítima pode exigir a substituição pelo **pacote demo oficial 6.6.1**, após verificar a assinatura PGP vinculada à identidade do fabricante e a compatibilidade/licença. Nenhum pacote foi descarregado, instalado, removido, substituído ou aceite à força. As funcionalidades exclusivas da licença paga não são consideradas disponíveis.

### Higienização e evidências finais

- [Run 40943189436](https://github.com/martaxi-boss/VPS/actions/runs/40943189436) — sessão inicial; falso negativo de parser local, posteriormente corrigido sem alterar o REA.
- [Run 40943711767](https://github.com/martaxi-boss/VPS/actions/runs/40943711767) — `sessions_found` direto no JSON do CLI verificado.
- [Run 40943930660](https://github.com/martaxi-boss/VPS/actions/runs/40943930660) — uma sessão autenticada; comando `ij` ainda bloqueado pela interface e terminou com erro.
- [Run 40944107143](https://github.com/martaxi-boss/VPS/actions/runs/40944107143) — diagnóstico exato `unreadable_output` por falta de confirmação do dispatcher gráfico; `hopper=6.6.0`.
- [Run 40944577193](https://github.com/martaxi-boss/VPS/actions/runs/40944577193) — **Cutter bridge v2 PASS e comando `ij` PASS**, encerramento e limpeza PASS.
- [Run 40944719135](https://github.com/martaxi-boss/VPS/actions/runs/40944719135) — workflow estável reposto; **Binwalk 3.1.0 PASS**, Frida discovery PASS, capturas de 8 e 30 processos **PASS**, `cleanup_incomplete` não observado; Cutter sem sessão ativa (correto após encerramento da GUI).
- Script de verificação específico preservado para reprodução sob demanda: `rea-linux/tests/rea_original_point2_targeted_gui_vendor_followup_20261029.py`. O workflow existente `.github/workflows/rea-mcp-transport-20261027.yml` foi **reposto** para `rea-linux/tests/rea_original_existing_optional_suppliers_point2_20261029.py`; segredos, fingerprint SSH e transportador original inalterados.
- Nenhuma nova ferramenta adicionada às 229, nenhum fornecedor duplicado, nenhuma instalação de componentes e nenhuma alteração a outros projetos.

**Estado final do ponto 2:** Binwalk e Frida mantêm PASS; **Cutter recuperado e PASS em sessão temporária sob demanda**; **Chromium bloqueado por política AppArmor**; **Hopper bloqueado por autenticidade/versão, depende de pacote demo oficial verificado e análise de licença**.
