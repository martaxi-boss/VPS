# P237 — Integridade integral de Evidence e Unknowns

Âmbito: somente o motor REA original. O utilitário offline não cria outro motor, MCP, servidor, Plugin ou Skill. Não importa, exporta ou altera o estado da VPS.

## Objetivo

O comparador verifica dois arquivos JSON completos já gerados e validados pelo REA original. Exige igualdade de todos os corpos Evidence, manifestações e revisões Unknown, não apenas contagens. Recusa duplicados, revisões ausentes, alterações de conteúdo, ficheiros inseguros e comparação do mesmo inode.

## Regressões isoladas

```bash
PYTHONPATH=rea-linux/owner python3 -m unittest discover -s rea-linux/certification/tests -p 'test_rea_p237_bundle_identity_guard.py' -v
```

Na preparação P237, 17/17 testes locais passaram usando dados sintéticos. Não se executou nenhuma ferramenta MCP, sessão binária, importação ou exportação.

## Execução futura (apenas após exportações autorizadas)

```bash
python3 rea-linux/owner/rea_p237_bundle_identity_guard.py --before /local/privado/evidence-antes.json --after /local/privado/evidence-depois.json
```

Os dois ficheiros têm de ser diferentes, privados (modo 0600), completos e previamente validados pelo parser do REA original. PASS devolve contagens e SHA-256, nunca o conteúdo; BLOCK termina com código 3. Não publicar arquivos privados no GitHub.

## Limites de segurança

- O comparador não autentica semanticamente IDs, manifestações nem Evidence por conta própria: usar primeiro o parser original REA.
- O SHA-256 semântico Python é uma impressão digital para comparar os dois documentos; não é a serialização RFC 8785 nativa do REA.
- close_binary(snapshot_path) pode selecionar apenas as evidências do alvo ativo; não substitui export_evidence_bundle de todo o estado.
- Exportação/importação e qualquer operação sensível requerem assinatura Ed25519 individual do proprietário, nunca reutilizada.
- Manter o bloqueio P232 de open_binary/close_binary até testes isolados e leitura MCP independente certificarem retenção durável.
- Não aumentar a contagem histórica: 116/208; as duas Evidence P217/P218 antigas continuam em falta.
