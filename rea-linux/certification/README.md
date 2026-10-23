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

## P26 — certificação funcional de `inspect_wasm_artifact` (23/10/2026)

- **`FULLY_CERTIFIED`**, para o contrato WASM em **Linux x64 com WABT 1.0.42**, através do motor MCP original permanente; outros ambientes e versões não herdam automaticamente esta certificação.
- Provas existentes preservadas: [Actions #40001710465](https://github.com/martaxi-boss/VPS/actions/runs/40001710465), módulo válido mínimo de oito bytes, e [#40011404653](https://github.com/martaxi-boss/VPS/actions/runs/40011404653), artefactos originais utilizados na comparação WASM posterior.
- [Actions #40024484529](https://github.com/martaxi-boss/VPS/actions/runs/40024484529): dois positivos adicionais (retorno completo e `detail:summary`) no mesmo módulo WASM controlado com importação tipada `env.id`, exportação `demo` e código existente mas **não executado**. Verificadas SHA-256 do input e da WAT, secções/limites, as três ferramentas WABT genuínas 1.0.42, dois candidatos locais e três referências JavaScript estáticas (`local-path-candidate`, `basename-candidates`, `unresolved`). O resumo mantém ID da Evidence e respetivas contagens, omitindo o texto WAT.
- **4/4 negativos MCP**: ficheiro WASM inválido, inexistente, candidato inexistente e JS mal codificado; **4/4 rejeições de schema MCP/ponte**: formato `detail` inválido, caminho vazio e listas de `glue_paths`/`candidate_paths` com mais de 16 elementos. As operações positivas apresentaram `isError` não verdadeiro, as rejeições `isError=true`.
- Hashes dos ficheiros inalterados, fontes temporárias eliminadas, PID da instalação original sem mudança, sem adquirir dados de rede e sem executar módulo.
- Não declarar WAT como código-fonte original, nem associações JavaScript como prova de execução. A certificação não inclui todos os formatos/propostas WASM nem carga maliciosa/volumosa.
- **Contagens:** 6 certificados no âmbito indicado; 16 com prova positiva limitada; 186 sem prova funcional positiva (208 no catálogo). Ponte estável restaurada e pedido consumido eliminado.


## P27 — certificação de `compare_wasm_interfaces` (23/10/2026)

- **`FULLY_CERTIFIED`** dentro do âmbito Linux x64 e WABT 1.0.42, com o REA MCP original e pares de Evidence observadas diretamente. Não implica garantia universal de execução/ligação WASM.
- Prova anterior reaproveitada sem duplicar: [Actions #40011404653](https://github.com/martaxi-boss/VPS/actions/runs/40011404653) — diferenças reais de quatro exportações `foo`, `stay`, `gone`, `born`, com identidades e hashes de ficheiros inalterados.
- [Actions #40024887858](https://github.com/martaxi-boss/VPS/actions/runs/40024887858): **2/2** fontes WASM validadas por WABT no MCP; **4/4** comparações de âmbitos (`imports`, `exports`, `both`, `reverse_imports`) corretas; **5/5** erros reais recusados, incluindo referência de Evidence ausente, âmbito inválido/em falta, campo extra e Evidence inline adulterada.
- Casos esperados: importações [adicionada 1, removida 1, alterada 1, igual 1, desconhecida 1]; exportações [0,0,1,1,0]; ambas [1,1,2,2,1]. Duplicados de `env.dup` retêm as duas entradas do lado esquerdo e uma do direito, classificados `unknown` com cobertura parcial, sem alegar compatibilidade de runtime.
- Fonte intacta, ficheiros temporários apagados e PID do serviço original estável. Nenhuma instalação ou reinício. Resposta MCP positiva com `isError` não verdadeiro.
- **Contagens:** 7 certificadas, 15 adicionais com prova positiva limitada, 186 ainda sem prova positiva. Ponte original restaurada; pedido temporário removido. Verificar o catálogo de 208 no Actions após a limpeza.

## P28 — certificação funcional de `inspect_sqlite_database` (23/10/2026)

- Estado `FULLY_CERTIFIED` **no contrato real de inspeção SQLite Linux x64 Node 24 e snapshots controlados**, sem alegar universalidade para todos os WAL danificados/ficheiros de produção/estados concorrentes.
- Prova reaproveitada de [Actions #39998433389](https://github.com/martaxi-boss/VPS/actions/runs/39998433389): pequeno snapshot offline, integridade SHA e Node24 confirmado no processo MCP.
- [Actions #40025654776](https://github.com/martaxi-boss/VPS/actions/runs/40025654776): no motor MCP original **4/4 modos positivos** `inventory`, `selected_table`, `columns+row_limit`, `database`, com valores JSON tipados de inteiro SQLite 64 bits, `olá` com `bytes_hex`, blob `00ff10`, REAL/null, índice/view/trigger conservados como declarações e truncamento correto. **WAL 4/4** verificações, incluindo checksum do ficheiro WAL e linha confirmada que depende do WAL. **6/6** erros legítimos do provedor: arquivo inválido/inexistente, tabela/coluna ausentes, tentativa de ler view e identificador com SQL embutido. Fontes intocadas, temporários eliminados, PID estável. A primeira tentativa [#40025537731](https://github.com/martaxi-boss/VPS/actions/runs/40025537731) falhou apenas no script de ensaio por erro `NameError`, posteriormente corrigido, não no REA.
- Duas rejeições de argumentos condicionais (`columns` ou `row_limit` sem `table`) **passaram no MCP original** no [Actions #40025818607](https://github.com/martaxi-boss/VPS/actions/runs/40025818607): `isError=true` e diagnóstico associado à tabela, fonte e serviço sem mudanças. Assim, **7/7 entradas inválidas recusadas pelo MCP original** no total.
- **Limitação residual da ponte:** o validador de pré-admissão JSON Schema existente **não rejeitou antecipadamente estas duas entradas condicionais**, embora o MCP original as tenha recusado. Permanecem como divergência documentada a endurecer, sem declarar falsamente 7/7 na validação da ponte; não houve execução não autorizada.
- Nada foi instalado nem reiniciado. A certificação é de inspeção estática, não de corrupção de WAL arbitrária, recuperação de dados eliminados, transações de produção ou concorrência extrema.
- Total acumulado: **8 certificadas**, **14 com prova funcional limitada**, **186 sem prova funcional positiva** do catálogo de 208. Três pedidos consumidos apagados e bridge original reposto; validar o catálogo pós-limpeza.

## P29 — certificação de `inspect_binary_layout` (23/10/2026)

- **`FULLY_CERTIFIED`** para o perfil Linux x64 com **pwntools 4.15.0 / pyelftools 0.33 / Unicorn 2.1.2** no motor original REA. Não se aplica automaticamente a outras arquiteturas.
- A prova de um ELF64 real [Actions #40003312811](https://github.com/martaxi-boss/VPS/actions/runs/40003312811) foi reutilizada, sem repetir o teste anterior.
- [Actions #40026611060](https://github.com/martaxi-boss/VPS/actions/runs/40026611060): novos ficheiros ELF64 autocriados com GCC **não executados**, cobrindo **3/3 tipos ET_REL/ET_EXEC/ET_DYN**. Estruturas de secções, segmentos, endereço de entrada, símbolos e relocalizações confrontadas de forma independente com os cabeçalhos reais dos ficheiros e `readelf`. Ligação estática e mitigação declaradas como inferências; base de carregamento e endereços runtime conservados como desconhecidos.
- `detail:summary` passou e manteve referências e contagens da Evidence. **5/5 erros funcionais rejeitados** pelo MCP: assinatura ELF inválida, arquitetura incompatível, truncamento, ficheiro acima de 32 MiB e caminho inexistente. **4/4 rejeições por schema** confirmadas no MCP e no validador da ponte.
- Fonte intacta, scripts e objetos temporários eliminados, serviço permanente sem reiniciar. A primeira execução [#40026519577](https://github.com/martaxi-boss/VPS/actions/runs/40026519577) parou na validação prévia do runner por sintaxe num ensaio; corrigida antes de contactar o MCP.
- Limites da certificação: não provaram todas as entradas ELF malformadas, stress/cancelamento ou uma tabela RELR não vazia; a interpretação de runtime permanece explicitamente desconhecida.
- **Contagem canónica:** 9 totalmente certificadas no respetivo perfil, 13 positivas limitadas, 186 sem prova funcional positiva, num catálogo real de 208. Dois pedidos consumidos retirados e bridge estável restaurada; verificar catálogo pós-limpeza.

## P30 — certificação de `inspect_packet_capture` (23/10/2026)

- **`FULLY_CERTIFIED`** no perfil **Linux x64 + TShark 4.x** para capturas armazenadas em ficheiros, não para aquisição de pacotes de interfaces de rede.
- Prova anterior reaproveitada sem a repetir: [Actions #39994380901](https://github.com/martaxi-boss/VPS/actions/runs/39994380901), um pacote IPv4/UDP num PCAP sintético, com SHA do artefacto e modo sem hardware.
- [Actions #40027107320](https://github.com/martaxi-boss/VPS/actions/runs/40027107320): **11/11** casos positivos no MCP original. PCAP com quatro frames TCP/UDP e PCAPNG com os mesmos pacotes; seleções de campos, filtro UDP/TCP, paginação por offset/limit, `match_limit:null`, seleção sem matches, `packet_limit` aplicado antes do filtro, modo `two_pass` verdadeiro/falso e `decode_as` para data no porto UDP 42000. Comparação com frames esperadas, janelas e correspondência dos resultados; SHA do binário fornecedor estável entre chamadas.
- **5/5 erros reais do TShark/MCP:** captura malformada, caminho ausente, filtro inválido, campo desconhecido e regra `decode_as` incorreta. **8/8 erros de schema** recusados no MCP original e na ponte: lista de campos vazia, packet_limit/match_limit zero, offset negativo, filtro vazio, tipo de `two_pass` incorreto, mais de 1024 campos e propriedade desconhecida.
- `hardware_acquisition=not-performed`, ficheiros temporários exclusivamente próprios, SHA e conteúdos originais inalterados, limpeza e PID do REA original confirmados. Nenhum target externo analisado nem motor reiniciado.
- **Limitações:** não testar todos os protocolos registados, capturas reais com falhas ou elevado volume, reconstrução de fluxos complexos, stress ou cancelamento. Requer recertificação em fornecedor/versão diferente.
- **Contagens canónicas:** 10 perfis de ferramentas FULLY_CERTIFIED, 12 adicionais com prova positiva limitada, 186 sem prova positiva. Não duplicar as 22 provas positivas. Pedido consumido apagado, ponte estável restaurada; execução final de catálogo ainda a verificar.

## P31 — certificação de `inspect_pcap_capture` (23/10/2026)

- **`FULLY_CERTIFIED` no perfil Linux x64 + fornecedores instalados TShark/capinfos**, apenas para síntese de ficheiros PCAP/PCAPNG guardados, sem captura de rede.
- Reutilizada a prova positiva [Actions #39984679548](https://github.com/martaxi-boss/VPS/actions/runs/39984679548), um pacote UDP e verificações de identidade/limpeza; não foi apagada nem reavaliada a fase.
- [Actions #40028203596](https://github.com/martaxi-boss/VPS/actions/runs/40028203596): **7/7 casos funcionais** no MCP original. Ficheiros próprios PCAP e PCAPNG com os mesmos 5 frames, 8 endpoints IPv4/IPv6, resposta DNS `lab.example` → `203.0.113.9`, ClientHello TLS `secure.example`, URI HTTP `/items?category=tools`, distribuição de protocolos e timestamps exatos. **Captura vazia** preservou `packet_count=0`, listas vazias e horários desconhecidos. `detail:summary` preservou Evidence e contagens sem a listagem completa.
- **2/2 falhas reais do MCP**: ficheiro inválido/inexistente. **5/5 inputs recusados** pelo MCP: caminho vazio, caminho ausente, caminho relativo rejeitado na camada runtime, opção extra `live_capture`, `detail` inválido. Para quatro dos cinco houve rejeição na validação JSON-schema da ponte; o caminho relativo não é rejeitado aí por `localPathStringSchema` e é recusado corretamente no MCP original, sem execução não autorizada.
- Capinfos apresenta encapsulação autêntica `ether` (não `Ethernet`); a pré-validação do ensaio tinha exigido a tradução, gerando falsos negativos em [#40027736210](https://github.com/martaxi-boss/VPS/actions/runs/40027736210). O ensaio de diagnóstico tinha inicialmente tentado consultar ficheiros já eliminados em [#40027995142](https://github.com/martaxi-boss/VPS/actions/runs/40027995142). [#40028076914](https://github.com/martaxi-boss/VPS/actions/runs/40028076914) confirmou fornecedor, identidade, DNS, paridade, captura vazia e integridade; a expectativa textual corrigida fechou os testes em #40028203596. **Nenhum desses problemas do teste alterou o motor REA.**
- Dados próprios apenas em `/dev/shm`, hashes intactos, temporários removidos, serviço MCP sem reiniciar. Não há prova de redacção de credenciais HTTP, DNS atribuído em casos multiquestão, stress, resposta DNS AAAA ou todos os protocolos/TLS.
- Total canónico: **11 ferramentas FULLY_CERTIFIED no perfil documentado**, 11 ferramentas adicionais com aprovação positiva limitada e 186 sem prova funcional positiva, no catálogo de 208. Bridge estável restaurada, quatro pedidos consumidos apagados e catálogo pós-limpeza a confirmar.

## P32 — certificação definitiva de leitura `get_evidence_bundle` (23/10/2026)

- **`FULLY_CERTIFIED`** para o contrato read-only de Evidence no **MCP original permanente Linux** com os 82 registos autenticados retidos pela sessão; não inclui inspeção de novos alvos.
- Mantidas provas anteriores sem repetição: leitura com filtros [#39950220193](https://github.com/martaxi-boss/VPS/actions/runs/39950220193) e casos do motor original isolado [#39969213976](https://github.com/martaxi-boss/VPS/actions/runs/39969213976).
- [Actions #40029183139](https://github.com/martaxi-boss/VPS/actions/runs/40029183139): **7/7 casos positivos**, abrangendo resumo sem filtros, bundle canónico completo com **82 Evidence** e igualdade de IDs/contagens, filtro por operação, Evidence ID e hash do artefacto, pesquisa sem correspondências e interseção vazia. O resultado tem o mesmo conteúdo antes/depois, sem importação, exportação ou mutação do estado.
- **6/6 negativas**: `detail:complete` incompatível com `filters` rejeitado pelo MCP; `detail` inválido, filtro inesperado, Evidence ID/hash mal formados e parâmetro extra rejeitados pelo MCP e pela pré-validação da ponte. `isError=true` nas rejeições e não verdadeiro nos casos positivos.
- A lista de revisões de unknowns nesta sessão estava vazia (`unknown_revisions=0`), pelo que a certificação não cobre cadeias complexas de revisões. Não há garantia de desempenho em bundles gigantes.
- Serviço original sem reinício, nenhum fornecedor instalado, sem acesso a produção dos outros projetos ou assinaturas contornadas. Pedido temporário e testes experimentais removidos; bridge estável restaurado e catálogo pós-limpeza ainda a reconfirmar.
- Contagem canónica: **12 FULLY_CERTIFIED**, **10 positivas mas não certificadas**, **186 sem prova positiva**, num catálogo de 208.

## P33 — certificação de leitura `evaluate_reconstruction_coverage` (23/10/2026)

- **`FULLY_CERTIFIED`** no âmbito Linux x64 do **MCP original permanente** com workspace sintético canónico de cinco Evidence criado pelo código-fonte original já presente na VPS. A execução não cria outro MCP nem muda dados de produção.
- Provas anteriores mantidas sem repetir: parcial no [Actions #39950220193](https://github.com/martaxi-boss/VPS/actions/runs/39950220193) e vários estados no MCP original em memória [#39969213976](https://github.com/martaxi-boss/VPS/actions/runs/39969213976).
- [Actions #40029650585](https://github.com/martaxi-boss/VPS/actions/runs/40029650585): cinco cenários positivos confirmados no servidor permanente: `ready` com evidência e verificador atuais, `partial` por package proof ausente, `failed` por verificador falhado, `unknown` por expiração e `unknown` por verificador ambíguo; quatro pedidos inválidos recusados. O primeiro oráculo esperava indevidamente `partial` ao retirar owners e superfícies/claims referenciados.
- [Actions #40029858500](https://github.com/martaxi-boss/VPS/actions/runs/40029858500): ensaio adicional **apenas dos quatro casos em dúvida**. `owners=[]` conserva a superfície mas devolve corretamente `unknown` devido aos motivos `owner-missing` e `verifier-result-incompatible`. Eliminar superfície ou claim com dependências pendentes produz `isError=true`. Mutação verdadeira do campo de autoridade de um Evidence, diferente do original, é rejeitada com `isError=true`.
- Total corrigido **6/6 cenários funcionais** + **7/7 entradas mal formadas/referências inválidas**. As restantes verificações previamente aprovadas não foram repetidas. O código-fonte original e o serviço REA não sofreram alterações; fornecedor e testes temporários eliminados da ponte.
- **Limites:** são decisões sobre cobertura fornecida e autenticada, não prova de reconstrução de aplicações reais. Não inclui volume extremo, todos os perfis/autoridades ou revisões de unknowns em produção.
- **Contagem:** 13 contratos individuais `FULLY_CERTIFIED`, 9 com prova positiva limitada e 186 sem prova positiva (208 ferramentas). Os dois pedidos da fase são removidos, bridge estável restaurada; revalidar catálogo pós-limpeza.


## P34 — três certificações de artefactos geridos .NET (23/10/2026)

- **`FULLY_CERTIFIED` nos perfis Linux x86_64/PE/CLI sintéticos controlados**: `inspect_managed_artifact`, `inspect_managed_members` e `inspect_managed_native_boundaries`. Conservam-se, sem repetição, as provas positivas do P01: [Actions #39945973782](https://github.com/martaxi-boss/VPS/actions/runs/39945973782) e [#39946140124](https://github.com/martaxi-boss/VPS/actions/runs/39946140124).
- [Actions #40030975590](https://github.com/martaxi-boss/VPS/actions/runs/40030975590), commit do pedido `a9ba7f18ecdd4898c47e510fa6069e4a774b2628`: **28/28 verificações via `tools/call` real no MCP permanente**, 208 ferramentas identificadas. Por ferramenta: **artefacto 9/9** (4 positivas + 5 negativas); **membros 11/11** (4 positivas + 7 negativas); **fronteiras nativas 8/8** (3 positivas + 5 negativas). Os casos positivos apresentaram `isError` não verdadeiro (campo ausente na resposta); as 17 rejeições previstas apresentaram `isError=true` sem erros de protocolo.
- Cobertura adicional sem repetir o ensaio inicial: metadados e classificação de um PE/CLI gerado com P/Invoke/ReadyToRun e MVID alternativo; seleção de tipo `Fixture.Program` num alvo previamente selecionado e seleção sem correspondências; `detail:summary` com Evidence ligada e SHA do alvo; PE não gerido; metadados inválidos corretamente degradados. Negativas: ficheiro inexistente, ficheiro não PE, `execute` não permitido, tipo inválido de `path`, `detail` inválido/indevido e listas de `type_names` vazias/duplicadas.
- Resultado cifrado do Actions autenticado e decifrado localmente, com correspondência ao pedido e SHA-256 de evidência `3d51b39827e31b830e9f521d9327dc6fe2bf2822a086b2c34ec17edb8892330c`. Integridade dos quatro artefactos sintéticos, imutabilidade do código-fonte REA e limpeza: **PASS**; PID do serviço original estável, sem reinstalação ou reinício.
- Limites: esta aprovação confirma **inspeção estática** de pequenos PE/CLI no perfil indicado. Não comprova carregamento de bibliotecas P/Invoke, execução CLR, exportações nativas reais, versões futuras nem tratamento exaustivo de entradas hostis de grande dimensão. Continuam aplicáveis as autorizações de `workspace` fora dos ensaios fixos de fonte própria.
- Higienização: código experimental de P34 removido, bridge canónica `ad6a6a7d3349caaa23be26aa1e5f95fa21521749` restaurada e pedido consumido eliminado no mesmo commit de certificação. O catálogo pós-limpeza deve ser observado em Actions.
- **Contagem canónica atualizada:** **16 FULLY_CERTIFIED**, **6 ferramentas adicionais com prova positiva limitada**, **186 sem prova funcional positiva**; **192 ainda pendentes de certificação completa**, de um total de 208.

## P35 — certificação de `analyze_javascript_application` (23/10/2026)

- **`FULLY_CERTIFIED` no perfil estático Linux x86_64 / aplicações JavaScript ESM locais e autocriadas**, via o MCP original permanente. A prova positiva anterior de duas fontes e versão de pacote foi conservada, sem repetição: [Actions #40018862425](https://github.com/martaxi-boss/VPS/actions/runs/40018862425) (P21).
- [Actions #40031757715](https://github.com/martaxi-boss/VPS/actions/runs/40031757715), commit de execução `70ff228115554c6ef8531ba8d0d765c9f531d939`: **7/7 testes funcionais positivos**: formato `directory`, integridade `fail`, seleção apenas de `main.js`, seleção e `summary` de dois ficheiros, limites de nós/unknowns, `record-and-continue` em fontes inalteradas, ficheiro JavaScript com erro sintático registado como diagnóstico, e `summary` de inventário retido. Nenhum ficheiro JavaScript foi executado.
- **17/17 negativas esperadas**: diretório inexistente e ficheiro fora do formato, mais 15 contratos de argumentos recusados pelo MCP original (tipos incorretos, `format`/`detail`/`integrity_policy` inválidos, `source_paths` vazio/inválido, opção `execute`, limites `max_semantic_*`, `max_heap_mb` e `analysis_timeout_ms` inválidos). Positivos com `isError` ausente/não verdadeiro, negativos com `isError=true` e sem falha do protocolo.
- Resultados cifrados autenticados com a chave de resposta efémera e o SHA-256 do pedido; prova verificável de resultado `acbbdcc3dfd15b21200ba252fe78b70f80664a15bda0ce5f6e2754ba76cb3b8e` (artefacto GitHub `12535172555`). Integridade das seis fontes sintéticas, código do motor e PID do processo permanente imutáveis; ficheiros temporários apagados. Original MCP devolveu as 208 ferramentas.
- **Limitações:** apenas aplicações ESM pequenas e controladas em diretório Linux. Não representa garantia para ASAR extensos, dependências hostis, Electron ativo, execução dinâmica, recursão de importações ou limites de memória extrema. A inspeção de código é estática; source paths não selecionados continuam desconhecidos.
- Higienização: código experimental removido, bridge estável restaurada ao blob `ad6a6a7d3349caaa23be26aa1e5f95fa21521749` e pedido `rea-linux/requests/javascript-p35-contract-20261023.json` eliminado. Confirmar catálogo pós-limpeza em Actions.
- **Contagem canónica:** **17 `FULLY_CERTIFIED`**, **5 positivas limitadas**, **186 sem prova funcional positiva**; **191 ainda pendentes de certificação completa** em 208.

## P36 — `inspect_firmware_regions`: assinatura estática Binwalk 3.1.0 (23/10/2026)

- **`FULLY_CERTIFIED` no perfil Linux original / Binwalk 3.1.0 / inspeção estática de assinaturas.** Reutilizada, sem repetição, a prova de GZIP com offset 64 de [Actions #40008229288](https://github.com/martaxi-boss/VPS/actions/runs/40008229288), P17.
- [Actions #40032203252](https://github.com/martaxi-boss/VPS/actions/runs/40032203252), pedido no commit `27975c0cd458b25ea94bae88b7dcb9550d880357`: **5/5 positivos**, incluindo uma assinatura GZIP nos offsets exatos 37 e 153, uma região ZIP e uma XZ detetadas, e zero regiões para uma sequência controlada sem assinatura. A resposta `structuredContent.normalized_result` foi validada: versão exata `3.1.0`, `coverage=signature_scan`, `input_size` correspondente, SHA dos alvos correlacionado, offsets e `size_basis=provider_reported_validation_unknown`.
- **9/9 rejeições**: ficheiro inexistente, diretório como alvo, `path` ausente/inválido/nulo e opções não suportadas `extract`, `detail`, `range` e `output_directory`. Respostas positivas com `isError` ausente/não verdadeiro, negativas com `isError=true`, sem erro JSON-RPC.
- Prova cifrada validada com RSA-OAEP/AES-GCM, SHA-256 do pedido e do resultado `0e118477b7af20f2f98350ec94d27ab82bcac11a2815d1eb29624f176ec46e0d`; artefacto `12535841134`. SHA dos ficheiros, integridade do repositório original e PID estável: **PASS**; ficheiros temporários eliminados. As 208 ferramentas permanecem disponíveis.
- **Limitações:** assinaturas são candidatos do fornecedor, não comprimentos validados de chunks nem garantias de extração/segurança; não testa firmware proprietário, nested extraction, Unblob ou execução de código. Certificação circunscrita aos formatos e entradas descritos.
- Higiene: ponte de ensaio retirada e bridge original restaurada (`ad6a6a7d3349caaa23be26aa1e5f95fa21521749`); pedido consumido eliminado. Confirmar catálogo pós-limpeza.
- **Estado:** **18 `FULLY_CERTIFIED`**, **4 adicionais positivas limitadas**, **186 sem prova positiva** e **190 ainda à espera de certificação funcional completa**.
