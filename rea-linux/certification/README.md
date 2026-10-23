# Certificação funcional do motor REA em Linux

**Âmbito vinculativo:** o único motor REA continua instalado no servidor Linux existente, em `/opt/rea-reversa/rea`. Todas as operações de análise, fornecedores, resultados e testes de certificação são executados no Linux, sem dependência obrigatória de uma distribuição específica.

A ligação existente `ChatGPT -> GitHub Actions -> SSH -> VPS Linux -> MCP em 127.0.0.1:8765/mcp` é apenas transporte para comandar o motor instalado. A nomenclatura legada de certos ficheiros da ponte não determina o sistema operativo do motor. Não mudar ou remover a ponte operacional durante esta normalização.

## Aprovação canónica

Cada uma das 208 ferramentas tem um contrato funcional próprio. Para aprovar uma ferramenta, registar: nome MCP e schema real, finalidade, alvo controlado guardado no Linux, resultado de `tools/call` (incluindo `isError`), comparação com resultado esperado, SHA-256 quando aplicável, invariância da entrada, limpeza da sessão/ficheiros, dependências e limitações, commit e ID da execução Actions.

Estados permitidos: `NOT_REVIEWED`, `FUNCTIONAL_PASS_SCOPED`, `FULLY_CERTIFIED`, `PROVIDER_UNAVAILABLE`, `FAILED`, `AUTHORIZATION_REQUIRED`, `NEGATIVE_PATH_CONFIRMED_POSITIVE_PENDING`, `POSITIVE_PATH_BLOCKED_VALID_SESSION`. Não confundir sucesso do transporte com correção funcional. Não aprovar uma ferramenta sem resultado demonstrado. Testes negativos são necessários antes da certificação completa.

## Continuação em fases

Primeiro reconciliar as evidências já obtidas no Linux, sem repetir ensaios. Depois selecionar ferramentas ainda não cobertas e testar por função; corrigir problemas numa área isolada; voltar a testar pelo MCP original; consolidar as provas neste diretório. A atividade de certificação não autoriza modificar, reiniciar ou reconfigurar o serviço de produção, nem instalar outro motor.

O ficheiro `functional-ledger.json` é o registo ativo. Evidências de execuções históricas continuam disponíveis nos respetivos commits e runs GitHub, mas não contam automaticamente como certificação funcional.

## Fase comprovada: GNU objdump no Linux

- Actions: https://github.com/martaxi-boss/VPS/actions/runs/39947962373
- Ferramenta: `inspect_with_objdump` (uma ferramenta, três operações)
- Ações funcionais: `file_headers`, `section_headers`, `disassemble`
- Alvo: `/usr/bin/true` no Linux original; SHA-256 `8a63c98320173f79e263115e10cefc170155e47d1fd4b5a70e4429d2699cae28`
- As três chamadas MCP devolveram resultado completo e não truncado, código de saída 0; alvo permaneceu inalterado.
- Validação da saída cifrada: correspondência SHA-256 de pedido, autenticação AES-GCM e digest do resultado; inspecionados os campos `structuredContent.normalized_result`.
- Interpretação: `FUNCTIONAL_PASS_SCOPED`, não certificação geral sem ensaio de entradas inválidas e outros perfis.

## Catálogo real de funcionalidades no Linux

- Actions: https://github.com/martaxi-boss/VPS/actions/runs/39948431340
- Catálogo: 208 descritores MCP únicos, 5 leitura, 120 workspace, 83 sensíveis.
- SHA-256 do resultado: `b06c75345f4e61de65a8035ea16e34a1c5644c41b590a5f2a8442b28b885ed8e`.
- Foram verificados os contratos reais por nome, descrição e parâmetros. Um contrato não substitui um teste funcional.
- O planeamento é por ferramenta e por operação, não por sistemas operativos de acesso.

## Higienização de transportes legados

- O diretório de pedidos em uso é **`rea-linux/requests/`**, não o diretório antigo.
- O único workflow operacional foi renomeado na interface do GitHub para **REA Linux VPS original MCP functional certification**.
- O nome histórico do ficheiro de workflow `.github/workflows/rea-android-bridge-20261022.yml` e os ficheiros `rea_mobile_*` continuam transitoriamente como *dependências técnicas da ponte existente*. Não são outra instalação nem alvo de testes. Apagar sem migrar todas as referências quebraria a ligação.
- O registo canónico antigo foi retirado do ramo ativo; commits e artefactos históricos são retidos para proveniência.
- Não apagar serviços em produção, sessões, chaves do proprietário, repositórios de outros projetos nem testes já confirmados.

## Grupo 1 — as cinco ferramentas de leitura

- Apenas as cinco ferramentas com classe MCP `read` foram chamadas; nove invocações reais, três workflows.
- [Run 39950220193](https://github.com/martaxi-boss/VPS/actions/runs/39950220193) — 5 chamadas, todas `isError != true`. Lista de unknowns vazia filtrada/paginada; resumo com 13 evidências; avaliação de reconstrução devolveu `partial` com 3 razões corretas.
- [Run 39950507161](https://github.com/martaxi-boss/VPS/actions/runs/39950507161) — 3 chamadas. Filtro de Evidence encontrou 3 registos, filtro inexistente 0; `verify_unknown_resolution` recusou corretamente um identificador inexistente, com `isError=true`.
- [Run 39950720098](https://github.com/martaxi-boss/VPS/actions/runs/39950720098) — 1 chamada `gdb_session_status` com identificador UUID de exemplo; devolveu `isError=true`, categoria `invalid_input`. Sem sessão GDB própria válida, a via positiva permanece pendente.
- Os três pedidos foram verificados com RSA-OAEP, AES-GCM e SHA-256 de pedido e resultado; nenhum resultado foi aceite apenas por o Actions estar verde.
- **Aprovação funcional limitada**: `list_unknowns`, `get_evidence_bundle`, `evaluate_reconstruction_coverage` (3/5).
- **Teste negativo correto, prova positiva pendente**: `verify_unknown_resolution` (1/5).
- **Via positiva bloqueada sem sessão existente autorizada**: `gdb_session_status` (1/5). Não foi iniciado qualquer processo GDB.
- Não inventar uma resolução nem criar sessões dinâmicas para aprovar artificialmente as duas ferramentas. A criação de pré-condições envolve outras classes de autorização e constitui uma fase separada.
- O resultado e os hashes detalhados estão em `functional-ledger.json`, fase `LINUX-P03-READ5-20261023`.

## Progresso do Grupo 1 — testes MCP isolados em Linux (fases P06 e P07)

As cinco ferramentas pertencem ao grupo `read`, mas têm pré-condições diferentes. A aprovação funcional **no motor MCP permanente** mantém-se diferente dos testes **do contrato MCP original em memória**.

- [P06 — Actions #39969213976](https://github.com/martaxi-boss/VPS/actions/runs/39969213976): quatro ensaios **PASS** do MCP original em processos Linux isolados, com teste real de paginação, evidências, cobertura e resolução de um registo com evidência `observed`. A ferramenta `verify_unknown_resolution` recebeu um ID válido e confirmou `valid=true` e `truthVerified=true`, após primeiro confirmar que ainda não estava resolvido; um ID inexistente foi recusado. O teste não escreveu na sessão MCP persistente.
- [P07 — Actions #39969907326](https://github.com/martaxi-boss/VPS/actions/runs/39969907326): duas operações **PASS** de `gdb_session_status` no MCP original de testes, para estado `ready` e diagnóstico de resposta MI mal codificada. **O GDB era emulado**; não constitui integração com um executável GDB real.
- Os cinco contratos de leitura têm alguma prova positiva de funcionamento no Linux: **3 provas positivas no MCP persistente, 1 apenas no MCP isolado com registo legítimo e 1 apenas com fornecedor GDB emulado**.
- **Pendências para certificação de integração completa:** `verify_unknown_resolution` com uma questão real no MCP persistente autorizada; `gdb_session_status` com um GDB real disponível e sessão criada mediante autorização sensível assinada.
- Não instalar novos fornecedores, não alterar o motor original, não iniciar depuradores reais sem a prova de autorização, não contar ensaios emulados como execução real de GDB.
- Os SHA-256 dos testes e os commits exatos constam do `functional-ledger.json`, nas fases P06 e P07.

## P22 - Sigrok offline sem relaxar a seguranca (2026-10-23)

- Actions: [40020212413](https://github.com/martaxi-boss/VPS/actions/runs/40020212413), [40020409580](https://github.com/martaxi-boss/VPS/actions/runs/40020409580), [40020641241](https://github.com/martaxi-boss/VPS/actions/runs/40020641241).
- O MCP original manteve **208** nomes. O sigrok-cli do host liga libsigrok e libusb; o servico REA usa `PrivateDevices=yes`, `DevicePolicy=closed` e nao permite AF_NETLINK. A causa unica da falha de inicializacao USB nao esta demonstrada.
- A simulacao APT para seis dependencias de build apresentou 23 instalacoes, **4 upgrades** e zero remocoes. **Instalacao global recusada**; houve um marcador temporario SAFE inicialmente incompleto, corrigido antes de qualquer alteracao. Nenhum pacote foi instalado.
- Docker/Podman nao estavam presentes; `bwrap` e `unshare` estavam acessiveis. A alternativa continua a ser uma build isolada com as releases oficiais libsigrok 0.5.2 e sigrok-cli 0.7.2, **sem USB**, antes de ligar o fornecedor REA.
- As duas ferramentas de sinais continuam por certificar no MCP permanente. Zero ferramentas adicionadas nesta fase. Nem o motor, nem o servico, nem o sandbox, nem os outros projetos foram alterados.
- Foram retirados os pedidos GitHub consumidos e o codigo experimental da ponte foi restaurado ao estado apos a correcao Kuna; provas e Actions historicos mantidos.

## P23 — certificação definitiva dos contratos funcionais comprovados (23/10/2026)

**Certificados agora, com âmbito Linux declarado:** `inspect_with_objdump` (ELF64 x86-64, oito modalidades e vias de erro), `inspect_pcap_client` (descoberta/versão de tshark e capinfos, pedido vazio e rejeição de extra), `inspect_apktool_client` (descoberta/versão do Apktool, pedido vazio e rejeição de extra). **3 ferramentas FULLY_CERTIFIED**, de 208 registadas; 19 outras têm aprovação positiva limitada; 186 não têm ainda aprovação funcional positiva.

- `inspect_with_objdump`: preservar três operações do [Actions 39947962373](https://github.com/martaxi-boss/VPS/actions/runs/39947962373). [Actions 40021674074](https://github.com/martaxi-boss/VPS/actions/runs/40021674074) fez 7/7 novos ensaios positivos (outras operações, símbolos, DWARF e arquitetura), integrou o fornecedor real e confirmou hashes/limpeza/PID. [Actions 40021854654](https://github.com/martaxi-boss/VPS/actions/runs/40021854654) distinguiu as rejeições MCP dos erros de fornecedor. [Actions 40022033849](https://github.com/martaxi-boss/VPS/actions/runs/40022033849) verificou erro real do objdump (exit code 1, `not recognized`) corretamente retido numa resposta MCP de Evidence com `isError` ausente. Entradas inexistentes e schemas inválidos são rejeitados pelo MCP original.
- `inspect_pcap_client` e `inspect_apktool_client`: reaproveitar anteriores [39984679548](https://github.com/martaxi-boss/VPS/actions/runs/39984679548) e [39986315538](https://github.com/martaxi-boss/VPS/actions/runs/39986315538). No [Actions 40022180504](https://github.com/martaxi-boss/VPS/actions/runs/40022180504), chamadas reais MCP com `isError` não verdadeiro, campos de versão/fornecedor observados, rejeição real dos parâmetros extra, e MainPID do serviço estável.
- A promoção não é universal: a certificação GNU objdump cobre Linux ELF64 x86-64 e todas as escolhas de operação aí ensaiadas, não todos os formatos e CPUs. Os dois contratos de cliente não certificam a leitura de PCAP ou descodificação de APK.
- O bridge de validação JSON permitiu um campo extra num pedido `architectures`, mas o MCP original recusou o pedido com `isError=true`; fica documentado para endurecimento posterior, não como sucesso indevido.
- Todos os pedidos temporários desta fase foram eliminados e a ponte estável com suporte ao Kuna restaurada. As provas anteriores e execuções GitHub permanecem disponíveis. A limpeza desencadeia validação final de catálogo, a verificar antes de declarar o transporte pós-higiene PASS.

## P24 — Certificação definitiva de `inspect_packet_fields` (23/10/2026)

- **Estado:** `FULLY_CERTIFIED` no perfil **Linux + TShark 4.x instalado**, com todas as variantes contratadas de seleção, filtros, paginação e erros representadas nos testes e fonte real independente.
- **Resultados reutilizados, sem os repetir:** [39994660187](https://github.com/martaxi-boss/VPS/actions/runs/39994660187), três operações positivas sobre UDP e protocolo inexistente.
- [Actions #40023117472](https://github.com/martaxi-boss/VPS/actions/runs/40023117472): 8/8 ensaios funcionais no MCP original (protocolos por omissão, protocolo exato TCP, campos UDP paginados, `limit:null`, consulta `PORT` indiferente a maiúsculas, página esgotada) e 4/4 rejeições reais de inputs inválidos. `isError` não verdadeiro nas respostas válidas e `isError=true` nos quatro inputs recusados. SHA do fornecedor consistente e PID do MCP estável.
- [Actions #40023335985](https://github.com/martaxi-boss/VPS/actions/runs/40023335985): verificadas diretamente contra a saída original `/usr/bin/tshark -G fields` as posições `source_line` de protocolos e campos UDP, tipos, descrições, base, máscara e nome. Perfil privado vazio; identidade SHA do binário comparada; diretório temporário limpo; REA sem reiniciar.
- **Contagens canónicas:** **4 FULLY_CERTIFIED**, **18 adicionais FUNCTIONAL_PASS_SCOPED**, **186 sem aprovação positiva**, total 208. Certificação limitada ao perfil de fornecedor e operações ensaiadas: a ferramenta não captura tráfego e não implica certificação da descodificação de ficheiros PCAP.
- Ponte experimental removida e bridge estável restaurada com zero pedidos pendentes; validar catálogo pós-limpeza antes de encerrar a fase.

## P25 — Certificação definitiva de `inspect_evm_interface` (23/10/2026)

- **Novo estado:** `FULLY_CERTIFIED` com âmbito **MCP original permanente Linux x64, EVMole 0.9.3, bytecode EVM plano** (o desempenho noutras arquiteturas/release não foi certificado).
- Reaproveitada a prova anterior no [Actions #39995775540](https://github.com/martaxi-boss/VPS/actions/runs/39995775540), sem repetir o ficheiro inicial.
- [Actions #40023775648](https://github.com/martaxi-boss/VPS/actions/runs/40023775648) passou **4/4 casos positivos** com bytecode próprio, idêntico nos carriers `raw`, `hex` com `0x`/maiúsculas/espaços exteriores, `hex` puro e modo `detail:summary`; devolveu provas de identidade SHA-256 do carrier e do bytecode descodificado, inferiu o seletor `0xa9059cbb`, deu a mesma inferência em raw/hex, preservou o ID da Evidence no resumo, sem executar contratos ou contactar redes.
- **5/5 casos negativos** recusados pelo MCP: hexadecimal ímpar, espaços interiores, contentor EF00 não suportado, ficheiro inexistente e tipo de encoding inválido. Ficou confirmada a integridade dos seis ficheiros temporários e a sua eliminação; REA MainPID estável.
- O resultado da ferramenta continua inferencial: completar este contrato não garante descoberta de todos os seletores, código implantado genuíno, hardfork, contratos grandes ou EOF. Novas versões dos fornecedores exigem recertificação.
- **Acumulado:** **5 FULLY_CERTIFIED**, **17 FUNCTIONAL_PASS_SCOPED**, **186 sem prova positiva**, num catálogo de 208; nenhuma ferramenta contada duas vezes. Ponte estável restaurada, pedido temporário apagado e nenhuma alteração ao motor de produção.
