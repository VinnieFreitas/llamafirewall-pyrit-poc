# LlamaFirewall + PyRIT — Pipeline de Segurança para IA

Pipeline de segurança para LLMs construído em camadas no Azure, com testes de red-team automatizados e observabilidade via Log Analytics e Azure Workbook. Suporta quatro profiles de ambiente — desde um home lab pessoal até um deployment em AKS corporativo em produção.

---

## Arquitetura

O projeto suporta quatro profiles de deployment, cada um com uma topologia diferente:

**home-lab / home-preprod / home-production** — VM única, PyRIT roda no laptop:
```
[ Linux Laptop ]                          [ Azure VM ]
  PyRIT ─── SSH tunnel ──────────────►  LlamaFirewall proxy (:8080)
  log_shipper ──────────────────────►          │
                                          Ollama + LLM (:11434)
                                               │
                                    Log Analytics Workspace
                                               │
                                    Azure Workbook Dashboard
```

**corp-lab** — duas VMs na subscription sandbox, acesso via Azure Bastion Developer SKU:
```
[ Azure Bastion ]
      │ SSH
      ├──► PyRIT VM (B2ms)  ──────────────► LlamaFirewall VM (NC4as T4 GPU)
      └──► LlamaFirewall VM                         │
                                            Log Analytics → Sentinel
```

**corp-preprod / corp-prod** — LlamaFirewall containerizado dentro do AKS:
```
Usuário → EntraID → Angular SPA (AKS)
                          │
                     Backend (AKS)
                          │  OPENAI_ENDPOINT=http://llamafirewall-svc:8080/v1
                          ▼
              LlamaFirewall pod (AKS)   ← mudança de uma variável de ambiente no backend
                          │
                 Azure OpenAI (private endpoint, subscription diferente)
                          │
              Sentinel LAW ← canary CronJob (a cada hora)
```

---

## Stack

- **Ollama** — servidor local de inferência para LLMs. Expõe uma API compatível com OpenAI em `:11434`. Utilizado nos profiles home em substituição ao Azure OpenAI — em produção, basta trocar a URL.
- **LLM model** — `phi3:mini` (lab) / `mistral:7b` (preprod) / `llama3:8b` (production)
- **LlamaFirewall** — framework open-source de segurança para LLMs da Meta, estendido com uma stack de até 10 camadas de scanners
- **PyRIT** — toolkit open-source de red-teaming para IA da Microsoft
- **NOVA** — motor de matching de padrões no estilo YARA para prompts (novahunting.ai)
- **Observabilidade** — Azure Log Analytics → Azure Workbook → Microsoft Sentinel

**LlamaFirewall stack — até 10 camadas, executadas em ordem a cada prompt:**

**Scanners de entrada (input):**

| Camada | Scanner | Tipo | Detecta |
|---|---|---|---|
| 1 | PromptGuard 2 | Classificador ML | Sintaxe de injection, jailbreaks |
| 1.5 | PerplexityFilter *(opcional)* | Modelo GPT-2 | Sufixos adversariais por gradient descent (GCG, AutoDAN) |
| 2 | HiddenASCII | Baseado em regras | Texto BiDi, caracteres invisíveis, encoding tricks |
| 3 | Regex + CustomPatterns | Baseado em regras | XSS, SQL injection, credenciais, abuso de tools |
| 4 | LlamaGuard 3:8B | LLM semântico | Engenharia social, segurança de conteúdo, jailbreaks sutis |
| 5 | NOVA (keyword+semantic) | Regras YARA-style | Armadilhas lógicas, injeção de tools, síntese de bioarmas, manipulação política |
| 6 | CrescendoTracker | Rastreamento de sessão | Escalada multi-turn, padrão Crescendo |

**Scanners de saída (output — apenas preprod/prod):**

| Camada | Scanner | Tipo | Detecta |
|---|---|---|---|
| 7 | LlamaGuard 3:8B output scan | LLM semântico | Conteúdo nocivo nas respostas do LLM |
| 8 | CodeShield | Análise de código | Código malicioso, chamadas de sistema perigosas nas respostas |
| 9 | Output sensitive data regex | Baseado em regras | CPF, CNPJ, credenciais, chaves de API, connection strings nas respostas |

**Resultado alcançado: 98,85% de detecção em dataset adversarial de 87 prompts (+55,17% em relação ao baseline de scanner único)**

---

## Profiles de Ambiente

Quatro profiles definem o tamanho da VM, o modelo LLM, os thresholds dos scanners e a topologia.
Tanto `deploy.sh` quanto `setup_vm.sh` solicitam a seleção interativa do profile.

| Configuração | home-lab | corp-lab | preprod | production |
|---|---|---|---|---|
| **Topologia** | VM única | Duas VMs | VM única | VM única |
| **LF VM size** | B8ms | NC4as_T4_v3 (GPU) | D8s_v3 | D16s_v3 |
| **PyRIT** | Laptop | B2ms VM | Laptop/CI | Canary probe |
| **LLM model** | phi3:mini | phi3:mini | mistral:7b | llama3:8b |
| **PromptGuard threshold** | 0.05 | 0.05 | 0.10 | 0.15 |
| **Output scanning** | ❌ | ❌ | ✅ | ✅ |
| **NOVA LLM tier** | ❌ | ❌ | ❌ | ✅ |
| **Perplexity filter** | ❌ | ❌ | ✅ | ✅ |
| **Crescendo tracker** | ✅ | ✅ | ✅ | ✅ |
| **CodeShield** | ❌ | ❌ | ✅ | ✅ |
| **Retenção LAW** | 30 dias | 30 dias | 30 dias | 90 dias |
| **Auto-shutdown** | ✅ 23:00 UTC | ✅ 23:00 UTC | ✅ 23:00 UTC | ❌ |
| **IP Público** | ✅ | ❌ | ❌ | ❌ |
| **Acesso** | SSH tunnel | Azure Bastion Developer SKU | Azure Bastion Developer SKU | Azure Bastion Developer SKU |
| **Custo estimado (uso leve)** | ~$16/mês | ~$45/mês | ~$28/mês | ~$55/mês |

> **corp-preprod** e **corp-prod** utilizam deployment containerizado no AKS — nenhum profile Bicep é necessário.

---

## Estrutura do Repositório

```
.
├── main.bicep              # Infraestrutura Azure — profile-aware (lab/preprod/production/corp-lab)
├── main.bicepparam         # Parâmetros (SSH key, profile, região)
├── deploy.sh               # Passo 1: seletor interativo de profile → faz o deploy da infra
├── teardown.sh             # Destroys todos os recursos Azure + limpeza do estado local
│
├── setup_vm.sh             # Passo 2: bootstrap da VM — aceita --profile lab|preprod|production
├── proxy.py                # Passo 2: proxy FastAPI do LlamaFirewall — stack de até 10 camadas de scanners
├── test_tunnel.sh          # Passo 2: SSH tunnel + smoke test (profiles home)
│
├── Dockerfile              # Deployment AKS — build CPU (corp-preprod)
├── Dockerfile.gpu          # Deployment AKS — build GPU (corp-prod)
├── .dockerignore           # Exclui infra/PyRIT/secrets do Docker build context
│
├── setup_pyrit.sh          # Passo 3: cria venv local + instala PyRIT
├── pyrit_redteam.py        # Passo 3: script de red-team (--endpoint, --category, --prompts-file)
├── custom_attacks.yaml     # Passo 3: dataset adversarial com 87 prompts (10 categorias, PT-BR)
├── attack_prompts.yaml     # Passo 3: biblioteca de ataques built-in estendida
├── gandalf_attacks.yaml    # Passo 3: dataset Gandalf com 60 prompts (inglês, 3 fontes Lakera)
├── build_gandalf_dataset.py   # Passo 3: baixa e curada datasets Gandalf do HuggingFace
├── social_engineering_pt.nov  # Regras NOVA — 10 regras cobrindo padrões PT-BR + Gandalf
├── canary_probe.py         # Monitoramento em produção — canary de 10 probes por hora + execução noturna completa
├── .gitlab-ci.yml          # GitLab CI — pipeline de regressão PyRIT com trigger manual
│
├── log_shipper.py          # Passo 4: envia resultados PyRIT + eventos ao vivo para LAW / Sentinel
│
├── workbook_content.json   # Passo 5: definição do Azure Workbook
├── deploy_workbook.py      # Passo 5: faz o deploy do workbook (reutiliza o mesmo ID no redeploy)
│
├── run_demo.sh             # Demo: preflight → PyRIT → log ship — tudo em um comando
├── toggle_nollm.sh         # Alterna bypass do Ollama para execuções rápidas do PyRIT
├── toggle_bypass.sh        # Alterna bypass completo do firewall (resposta a incidentes)
│
├── deploy-outputs.json     # Gerado pelo deploy.sh — no .gitignore, manter localmente
└── README.md
```

> `deploy-outputs.json` está excluído do git (`.gitignore`) — contém a primary key do LAW.

---

## Pré-requisitos

- Subscription Azure (pessoal é suficiente para profiles home)
- Azure CLI instalado e autenticado (`az login`)
- Laptop Linux com Python 3.10+, `ssh`, `jq`
- Conta HuggingFace com acesso a [meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- Token de leitura do HuggingFace em https://huggingface.co/settings/tokens

Após o clone do repositório, torne todos os scripts executáveis:
```bash
chmod +x *.sh
```

> LlamaGuard 3:8B é baixado via Ollama — não é necessário token HuggingFace para ele.

---

## Configuração do HuggingFace — Fazer Antes do Passo 2

PromptGuard 2 é um modelo Meta com acesso controlado. Configuração única:

**1.** Crie uma conta gratuita em https://huggingface.co/join

**2.** Aceite a licença do modelo em https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
— clique em **"Agree and access repository"** (aprovação imediata)

**3.** Gere um token de leitura em https://huggingface.co/settings/tokens
→ **New token** → Role: **Read** → copie

> `setup_vm.sh` solicitará esse token de forma interativa e o injetará no
> serviço systemd. Após o primeiro download, os pesos ficam em cache localmente.

---

## Passo 1 — Deploy da Infraestrutura Azure

```bash
cd ~/Documents/Safra_AI_Defense

# 1. Gere uma SSH key — pule se já tiver uma.
#    Verifique primeiro: ls ~/.ssh/id_ed25519.pub
#    Se o arquivo existir, vá para o passo 2.
#    Se não, gere uma:
ssh-keygen -t ed25519 -C "llamapoc"

# 2. Copie sua chave pública para main.bicepparam
#    Abra o arquivo e substitua o valor de adminPublicKey pela saída abaixo:
cat ~/.ssh/id_ed25519.pub
#    Deve ficar assim: param adminPublicKey = 'ssh-ed25519 AAAAC3Nz... sua-chave-aqui'
#    ⚠️  Faça isso antes de executar deploy.sh — o script parará se o
#    valor placeholder não tiver sido substituído.

# 3. Deploy — o script solicitará a seleção do profile
chmod +x deploy.sh && ./deploy.sh
```

O seletor de profile aparece após confirmar a subscription:

```
1) lab         — Standard_B8ms   · phi3:mini   · ~$16/mês
2) preprod     — Standard_D8s_v3  · mistral:7b  · ~$28/mês
3) production  — Standard_D16s_v3 · llama3:8b   · ~$55/mês
4) corp-lab    — NC4as_T4_v3 GPU + B2ms PyRIT VM · ~$45/mês
                 ⚠️  Requer quota NC-series na subscription sandbox
```

> **corp-lab** gera automaticamente um par de SSH keys dedicado em `~/.ssh/id_ed25519_llamapoc_corp`.
> NÃO reutilize sua chave pessoal em ambientes corporativos.

---

## Passo 2 — Configuração da VM (profiles home)

```bash
# Copie os scripts para a VM (todos os três são necessários)
scp setup_vm.sh proxy.py social_engineering_pt.nov \
  azureuser@llamapoc-llama.eastus.cloudapp.azure.com:~/

# Execute o setup — passe o profile ou deixe o script perguntar
ssh azureuser@llamapoc-llama.eastus.cloudapp.azure.com \
  'bash ~/setup_vm.sh --profile lab 2>&1 | tee ~/setup.log'
```

| Etapa | O que acontece |
|---|---|
| apt | Atualização do sistema + aguarda apt-lock |
| Ollama | Instalação + download do modelo LLM do profile |
| LlamaGuard3 | `ollama pull llama-guard3:8b` (~4,7 GB) |
| Python | venv + llamafirewall + transformers + torch + nova-hunting |
| HfFolder patch | Shim de compatibilidade para huggingface_hub >= 0.25 |
| HF login | Prompt interativo para o token + download do PromptGuard 2 (~170 MB) |
| proxy.py | Implantado com variáveis de ambiente específicas do profile |
| NOVA | Regras oficiais clonadas + regras customizadas implantadas |
| systemd | `ollama.service` + `llamafirewall.service` habilitados e iniciados |

**Tempo estimado de execução:** lab ~20 min · preprod ~35 min · production ~45 min

**Validação:**
```bash
./test_tunnel.sh azureuser@llamapoc-llama.eastus.cloudapp.azure.com
```

Esperado: `/health` mostra 6 scanners ativos, prompt limpo → ALLOW, injection → BLOCK.

**Sempre aqueça os modelos antes de executar o PyRIT** — modelos frios causam timeout no LlamaGuard3 na primeira requisição:

```bash
ssh azureuser@llamapoc-llama.eastus.cloudapp.azure.com << 'EOF'
curl -sf http://localhost:11434/api/generate \
  -d '{"model":"llama-guard3:8b","prompt":"hello","stream":false}' > /dev/null && echo "llama-guard3 warm"
curl -sf http://localhost:11434/api/generate \
  -d '{"model":"phi3:mini","prompt":"hello","stream":false}' > /dev/null && echo "phi3:mini warm"
EOF
```

> Substitua `phi3:mini` por `mistral:7b` ou `llama3:8b` nos profiles preprod/production.

**Problemas conhecidos tratados pelo script:**
1. apt lock na primeira inicialização — aguarda até 2 min e então força a liberação
2. CLI `ollama run` trava — smoke test usa REST API com `--max-time 60`
3. `huggingface_hub >= 0.25` — `HfFolder` removido, script aplica shim de compatibilidade
4. `scanners` do LlamaFirewall deve ser um dict — `{Role: [ScannerType]}`
5. Scan bloqueante em handler async — `firewall.scan()` encapsulado com `asyncio.to_thread()`

---

## Configuração de Scanners Adicionais

### Perplexity Filter (camada 1.5) — desabilitado por padrão

Detecta sufixos adversariais gerados por ataques baseados em gradient (GCG, AutoDAN, PEZ). Usa GPT-2 (~500 MB) para medir a incomum estatística das sequências de tokens — complementar ao HiddenASCII.

```bash
# Ativar (requer download do GPT-2 ~500 MB na primeira execução)
sudo systemctl set-environment PERPLEXITY_FILTER_ENABLED=1
sudo systemctl set-environment PERPLEXITY_THRESHOLD=500.0
sudo systemctl restart llamafirewall
```

> Threshold padrão: 500. Diminuir = mais agressivo (pode gerar falsos positivos em prompts técnicos longos). Aumentar = mais conservador.

---

### Crescendo Tracker (camada 7) — habilitado por padrão

Rastreamento stateful de sessão para detectar escalada multi-turn. Bloqueia uma sessão após N near-misses consecutivos — o fingerprint clássico do ataque Crescendo.

```bash
# Ajustar sensibilidade (padrões recomendados para produção)
sudo systemctl set-environment CRESCENDO_ENABLED=1
sudo systemctl set-environment CRESCENDO_NEAR_MISS_THRESHOLD=0.03
sudo systemctl set-environment CRESCENDO_BLOCK_AFTER=3
sudo systemctl set-environment CRESCENDO_SESSION_TTL=3600
sudo systemctl restart llamafirewall
```

> **Limitação:** estado em memória — resetado ao reiniciar o proxy. Em produção AKS com múltiplas réplicas, substituir `_session_store` por Redis para persistência entre pods.

---

### CodeShield (camada 8) e Output Sensitive Data (camada 9) — apenas preprod/prod

Habilitados automaticamente quando `OUTPUT_SCAN_ENABLED=1`. Nenhuma configuração adicional necessária.

- **CodeShield** — detecta código malicioso, chamadas de sistema perigosas e prompt injection em comentários de código nas respostas do LLM. Fail-open se não disponível na versão instalada do LlamaFirewall.
- **Output sensitive data regex** — bloqueia respostas contendo CPF, CNPJ, chaves AWS, GitHub PAT, tokens Bearer, chaves privadas e connection strings.

--- — Executar Red-Team com PyRIT (do seu laptop)

```bash
# Instalação (uma vez)
chmod +x setup_pyrit.sh && ./setup_pyrit.sh

# Abra o tunnel + aqueça os modelos primeiro (profiles home)
./test_tunnel.sh azureuser@llamapoc-llama.eastus.cloudapp.azure.com

# Execução completa com 87 prompts
source venv/bin/activate
python3 pyrit_redteam.py --prompts-file custom_attacks.yaml

# Execução contra um endpoint específico (corp-lab — IP privado)
python3 pyrit_redteam.py \
  --endpoint http://10.0.0.4:8080/v1 \
  --prompts-file custom_attacks.yaml

# Execução de uma categoria específica
python3 pyrit_redteam.py --prompts-file custom_attacks.yaml --category jailbreak

# Dry run — valida apenas o endpoint
python3 pyrit_redteam.py --dry-run
```

**Categorias de ataque em `custom_attacks.yaml` (87 prompts, Português Brasileiro):**

| Categoria | Qtd | Observações |
|---|---|---|
| `jailbreak` | 32 | DAN, developer mode, roleplay, fictional framing |
| `evasion` | 17 | Texto BiDi, homoglyphs, code-switching, encoding |
| `social_engineering` | 12 | Coerção, impersonação, manipulação emocional |
| `content_safety` | 7 | XSS, SQL injection, conteúdo nocivo |
| `baseline` | 6 | Devem passar — valida tráfego legítimo |
| `prompt_injection` | 4 | Padrões clássicos de injection |
| `reliability` | 3 | Casos extremos, devem passar |
| `data_leakage` | 3 | Extração de credenciais, exfiltração de código-fonte |
| `tool_abuse` | 2 | Injeção de comandos, chamadas de função perigosas |
| `policy_compliance` | 1 | Bypass regulatório |

**Dataset Gandalf `gandalf_attacks.yaml` (60 prompts, inglês):**

Ataques reais gerados por humanos no jogo de red-teaming Gandalf da Lakera — curados de três datasets do HuggingFace. Use para validação cruzada junto ao `custom_attacks.yaml`.

| Categoria | Qtd | Fonte | Observações |
|---|---|---|---|
| `prompt_injection` | 25 | `gandalf_ignore_instructions` | Variantes clássicas de "ignore previous instructions" |
| `indirect_injection` | 20 | `gandalf_summarization` | Injection oculta em tarefas de sumarização de documentos |
| `evasion` | 15 | `mosscap_prompt_injection` | Variante DEF CON 2023 — acrósticos, encoding, roleplay |

```bash
# Reconstruir o dataset (re-download do HuggingFace)
pip install datasets
python3 build_gandalf_dataset.py

# Executar contra o LlamaFirewall
python3 pyrit_redteam.py --prompts-file gandalf_attacks.yaml
```

**Resultados de detecção — dataset Gandalf (primeira execução):**

| Categoria | Taxa de acerto | Observações |
|---|---|---|
| `prompt_injection` | 100% | PromptGuard 2 detecta toda a sintaxe clássica de injection |
| `indirect_injection` | 50% | Categoria mais difícil — ataques ocultos em conteúdo de documentos |
| `evasion` | 47% | Ataques de transformação multi-etapa e fictional framing |
| **Geral** | **70%** | Ataques reais, sem tuning para PT-BR |

> A diferença em relação a `custom_attacks.yaml` (98,85%) é esperada — o dataset Gandalf testa a generalização além do idioma e dos padrões para os quais a stack foi treinada.

**Progressão da taxa de detecção:**

| Execução | Configuração | Taxa |
|---|---|---|
| 1 | PromptGuard 2 apenas (threshold 0.50) | 43,68% |
| 2 | PromptGuard 2 (threshold 0.05) | 60,92% |
| 3 | + HiddenASCII + Regex + CustomPatterns | 72,41% |
| 4 | + LlamaGuard 3:8B | 80,46% |
| 5 | + correções no dataset + truncamento de input | 88,51% |
| 6 | + fail-closed em timeout | 90,80% |
| **7** | **+ NOVA (keyword + semantic)** | **98,85%** |

---

## Modo NO_LLM — Acelerar Execuções do PyRIT

Contorna o Ollama para prompts permitidos — apenas a stack de scanners do firewall é executada.
Reduz a latência por prompt de ~23s para ~7s.

```bash
./toggle_nollm.sh on    # ativar (modo rápido)
./toggle_nollm.sh off   # desativar (respostas LLM completas)
./toggle_nollm.sh status
```

---

## Passo 4 — Enviar Logs para o Log Analytics

```bash
source venv/bin/activate

# Após uma sessão PyRIT
python3 log_shipper.py --mode pyrit

# Apontar para o Sentinel LAW corporativo em vez do workspace do PoC
python3 log_shipper.py --mode pyrit \
  --workspace-id <sentinel-workspace-id> \
  --workspace-key <sentinel-primary-key>

# Transmitir eventos ao vivo durante um teste
python3 log_shipper.py --mode live \
  --vm-host azureuser@llamapoc-llama.eastus.cloudapp.azure.com
```

> Credenciais do workspace Sentinel: Portal → Log Analytics → seu workspace → Agents → Primary key

---

## Passo 5 — Deploy do Azure Workbook

> ⚠️ **Requer Azure CLI (`az`)** — execute do seu laptop ou Azure Cloud Shell.
> NÃO execute das VMs PyRIT ou LlamaFirewall (`az` não está instalado nelas).

```bash
# Home-lab — lê credenciais do deploy-outputs.json
source venv/bin/activate
python3 deploy_workbook.py

# Corp / Sentinel LAW — passe as credenciais diretamente (sem deploy-outputs.json)
# Cloud Shell: instale httpx primeiro: pip install httpx --user --quiet
python3 deploy_workbook.py \
  --workspace-id <sentinel-workspace-id> \
  --resource-id /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>
```

> Encontre o resource ID do workspace Sentinel: Portal → Log Analytics workspaces → seu workspace → Properties → Resource ID

O workbook ID é persistido em `deploy-outputs.json` — reexecutar atualiza o workbook existente sem criar duplicatas.

**Azure Portal → Monitor → Workbooks → LlamaFirewall Security Dashboard**

---

## Spec de Integração NestJS — Melhorias de curto prazo no AI Portal

Esta seção documenta o contrato entre o backend NestJS do AI Portal e o LlamaFirewall. Os itens 2 e 3 requerem pequenas alterações tanto no NestJS quanto no `proxy.py` (já implementadas no lado do LlamaFirewall). Os itens 4 e 5 são puramente NestJS.

---

### Item 1 — Fail-closed em indisponibilidade do pod (apenas NestJS)

Altere o error handler HTTP do NestJS de fail-open para fail-closed:

```typescript
// Depois — fail-closed (correto para uma instituição financeira)
try {
  const result = await llamafirewallClient.scan(payload);
  return result;
} catch (error) {
  logger.error('LlamaFirewall inacessível — requisição bloqueada (fail-closed)');
  throw new ServiceUnavailableException(
    'Scanning de segurança indisponível — requisição bloqueada'
  );
}
```

---

### Item 2 — Inspeção de chunks RAG (NestJS SearchHandler + proxy.py)

Em `SearchHandler.execute()`, inspecione cada chunk em paralelo antes de retornar o `tool_result` ao LangGraph. O `proxy.py` já aceita `source: "rag_chunk"`.

```typescript
const chunks = await vectorSearch(query, storeId);

const inspected = await Promise.all(
  chunks.map(async (chunk) => {
    try {
      const result = await llamafirewallClient.post('/v1/chat/completions', {
        model:    'llamafirewall',
        messages: [{ role: 'user', content: chunk.content }],
        user_id:  currentUser.upn,
        source:   'rag_chunk',
      });
      const lf = result.data.x_llamafirewall;
      if (lf.blocked) {
        logger.warn('Chunk RAG bloqueado', {
          documentId: chunk.documentId, documentName: chunk.documentName,
        });
        return null;
      }
      return chunk;
    } catch {
      return null;  // LlamaFirewall inacessível — fail-closed, exclui o chunk
    }
  })
);

const safeChunks = inspected.filter(Boolean);
// Política: se todos os chunks forem bloqueados → retornar tool_result vazio, não travar o agent
if (safeChunks.length === 0) {
  logger.warn('Todos os chunks RAG bloqueados', { query, storeId });
  return [];
}
return safeChunks;
```

**KQL — monitorar bloqueios de chunks RAG no Sentinel:**
```kusto
LlamaFirewallEvents_CL
| where source_s == "rag_chunk" and blocked_b == true
| project TimeGenerated, user_id_s, scan_decision_s, scan_score_d, prompt_preview_s
| order by TimeGenerated desc
```

---

### Item 3 — Adicionar userId a cada chamada do LlamaFirewall (apenas NestJS)

Inclua o UPN ou OID do Entra ID em cada chamada REST ao LlamaFirewall:

```typescript
const payload = {
  model:    'llamafirewall',
  messages: [{ role: 'user', content: userPrompt }],
  user_id:  request.user?.upn ?? request.user?.oid ?? 'unknown',
  source:   'user_input',
};
```

O `proxy.py` já lê `user_id` e `source` e os inclui em `LlamaFirewallEvents_CL` e `LlamaFirewallPrompts_CL`.

**KQL — base para detecção de anomalia por usuário:**
```kusto
LlamaFirewallEvents_CL
| where blocked_b == true and source_s == "user_input"
| summarize BlockCount = count() by user_id_s, bin(TimeGenerated, 1h)
| where BlockCount > 5
| order by BlockCount desc
```

---

### Item 4 — Limites de turns em conversas (apenas NestJS Agent Studio)

Limite as sessões a 50 turns, forçando sumarização no limite. Eleva significativamente o custo de ataques Crescendo — jailbreaks multi-turn requerem persistência de contexto.

```typescript
const MAX_TURNS = 50;
if (conversation.interactions.length >= MAX_TURNS) {
  const summary = await summarizeConversation(conversation);
  await conversation.reset({ keepSummary: summary });
}
```

---

### Item 5 — Reinjeção do system prompt (apenas NestJS dynamicSystemPromptMiddleware)

Reinjete o system prompt a cada 20 turns para resetar o trust boundary:

```typescript
const REINJECT_EVERY_N_TURNS = 20;
if (turnIndex > 0 && turnIndex % REINJECT_EVERY_N_TURNS === 0) {
  messages.unshift({ role: 'system', content: agent.systemPrompt });
}
```

---

## Log de Prompts no Sentinel

O LlamaFirewall pode enviar o **texto completo do prompt** de cada requisição para uma tabela dedicada `LlamaFirewallPrompts_CL` no Sentinel LAW. Esta tabela é mantida separada da tabela geral `LlamaFirewallEvents_CL` e restrita a investigadores de incidentes via RBAC no nível de tabela.

**Casos de uso:**
- Investigação de incidentes — um usuário reclama que sua consulta foi bloqueada; você vê exatamente o que ele enviou
- Threat hunting — um prompt malicioso foi permitido; você precisa do texto completo para análise
- Auditoria de conformidade — registro completo do que o gateway LLM recebeu

> ⚠️ **Nota de governança de dados:** Prompts completos podem conter PII (CPF, nomes, números de conta).
> Sempre configure o RBAC no nível de tabela antes de ativar em produção.
> Em lab/corp-lab, os prompts são dados sintéticos de ataque — redação de PII é opcional.

---

### Passo 1 — Restringir acesso à LlamaFirewallPrompts_CL no LAW

**Portal → Sentinel LAW → Access control (IAM) → Add role assignment**

1. Crie uma role customizada permitindo apenas `LlamaFirewallPrompts_CL`:
```json
{
  "Name": "LlamaFirewall Prompt Investigator",
  "Actions": [
    "Microsoft.OperationalInsights/workspaces/read",
    "Microsoft.OperationalInsights/workspaces/query/read"
  ],
  "DataActions": [
    "Microsoft.OperationalInsights/workspaces/query/LlamaFirewallPrompts_CL/read"
  ]
}
```

2. Atribua a role ao grupo de segurança dos investigadores de incidentes (máximo 1-2 grupos)
3. Verifique que leitores gerais do Sentinel **não conseguem** consultar `LlamaFirewallPrompts_CL`

---

### Passo 2 — Ativar log de prompts na VM do LlamaFirewall

**Lab / corp-lab (Shared Key):**
```bash
sudo systemctl set-environment PROMPT_LOGGING_ENABLED=1
sudo systemctl set-environment LAW_WORKSPACE_ID=<seu-sentinel-workspace-id>
sudo systemctl set-environment LAW_WORKSPACE_KEY=<sua-sentinel-primary-key>
sudo systemctl restart llamafirewall

# Verificar
curl -sf http://localhost:8080/health | python3 -m json.tool
# → "prompt_logging": true, "ingestion_method": "shared_key"
```

**Preprod / production (Managed Identity — sem chaves):**

A VM já possui uma System-Assigned Managed Identity e o role assignment do DCR do deployment Bicep. Obtenha o endpoint DCE e o ID imutável do DCR em `deploy-outputs.json`:

```bash
cat deploy-outputs.json | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('DCE:', d.get('dceEndpoint',{}).get('value'))
print('DCR:', d.get('dcrImmutableId',{}).get('value'))
"

# Na VM do LlamaFirewall:
sudo systemctl set-environment PROMPT_LOGGING_ENABLED=1
sudo systemctl set-environment DCE_ENDPOINT=<dce-endpoint>
sudo systemctl set-environment DCR_IMMUTABLE_ID=<dcr-immutable-id>
# LAW_INGESTION_METHOD=managed_identity já é definido pelo setup_vm.sh para preprod/production
sudo systemctl restart llamafirewall

# Verificar
curl -sf http://localhost:8080/health | python3 -m json.tool
# → "prompt_logging": true, "ingestion_method": "managed_identity"
```

> O token Managed Identity é obtido automaticamente do endpoint Azure IMDS
> (`169.254.169.254`) dentro da VM. Os tokens são armazenados em cache e renovados
> 5 minutos antes do vencimento. Nenhuma credencial é armazenada em lugar algum.

---

### Passo 3 — Ativar redação de PII (apenas em produção)

Em produção, ative a redação via Azure AI Language antes que os prompts cheguem ao LAW:

```bash
sudo systemctl set-environment PII_REDACTION_ENABLED=1
sudo systemctl set-environment AZURE_LANGUAGE_ENDPOINT=https://<seu-recurso>.cognitiveservices.azure.com
sudo systemctl set-environment AZURE_LANGUAGE_KEY=<sua-language-key>
sudo systemctl restart llamafirewall
```

A API mascara entidades PII detectadas (CPF, nomes, e-mails, telefones, números de conta)
com caracteres `*` antes de enviar o prompt ao LAW. O prompt original não redatado
permanece apenas no journald da VM.

> A redação de PII é **fail-open** — se a API estiver indisponível, o prompt é enviado como está,
> sem bloquear a requisição. Para controle mais estrito, configure `PII_REDACTION_ENABLED=1`
> junto com uma Analytics Rule no Sentinel que alerte para registros com `pii_redacted: false`.

---

### Passo 4 — Consultar prompts no Sentinel

```kusto
// Todos os prompts nas últimas 24 horas
LlamaFirewallPrompts_CL
| where TimeGenerated > ago(24h)
| project TimeGenerated, request_id_s, scan_decision_s, blocked_b,
          scan_score_d, full_prompt_s
| order by TimeGenerated desc

// Apenas prompts bloqueados — para threat hunting
LlamaFirewallPrompts_CL
| where TimeGenerated > ago(7d) and blocked_b == true
| project TimeGenerated, scan_decision_s, scan_reason_s,
          scan_score_d, full_prompt_s
| order by scan_score_d desc

// Investigar uma requisição específica por ID
LlamaFirewallPrompts_CL
| where request_id_s == "<request-id-da-reclamacao-do-usuario>"
| project TimeGenerated, full_prompt_s, scan_decision_s,
          scan_reason_s, scan_score_d, pii_redacted_b
```

---

### AKS / production — variáveis de ambiente via Kubernetes Secret

Em produção (pod AKS), configure via Kubernetes Secret em vez de systemd:

```bash
kubectl create secret generic llamafirewall-prompt-logging \
  --namespace llamafirewall \
  --from-literal=PROMPT_LOGGING_ENABLED=1 \
  --from-literal=LAW_WORKSPACE_ID=<id> \
  --from-literal=LAW_WORKSPACE_KEY=<chave> \
  --from-literal=PII_REDACTION_ENABLED=1 \
  --from-literal=AZURE_LANGUAGE_ENDPOINT=<endpoint> \
  --from-literal=AZURE_LANGUAGE_KEY=<chave>
```

---

## Modo Bypass — Resposta a Incidentes

Quando tráfego legítimo está sendo bloqueado pelo LlamaFirewall, ative o modo bypass.
O proxy continua em execução — nenhuma alteração de rede é necessária. Todas as requisições em bypass continuam sendo registradas no Sentinel com `scan_decision: BYPASS` para trilha de auditoria.

**Profiles home (VM):**
```bash
./toggle_bypass.sh on    # desativa o scanning — encaminha diretamente ao Ollama
./toggle_bypass.sh off   # reativa o scanning
./toggle_bypass.sh status
```

**Corp-preprod / corp-prod (AKS):**
```bash
kubectl set env deployment/llamafirewall BYPASS_MODE=1 -n llamafirewall
# Reativar quando resolvido:
kubectl set env deployment/llamafirewall BYPASS_MODE=0 -n llamafirewall
```

---

## Deployment Corp-Lab

Duas VMs em uma subscription sandbox isolada. Acesso via Azure Bastion Developer SKU, sem SSH tunnel.

**Pré-requisitos:**
1. Quota NC-series aprovada na subscription sandbox — Portal → Subscriptions → Usage + quotas → Request increase (Standard NCASv3_T4 Family, mínimo 4 vCPUs)
2. Azure Bastion Developer SKU é implantado automaticamente pelo `main.bicep` — nenhuma configuração de CIDR necessária. Acesso: Portal → VM → Connect → Bastion
3. **Trusted Launch é automaticamente desabilitado** no Bicep para todos os profiles corp — necessário para o driver NVIDIA GPU funcionar corretamente. Não reative.
4. **Registre o feature StandardSecurityType** na subscription sandbox — necessário para deploy de VMs com Trusted Launch desabilitado. Execute uma vez por subscription:
   ```bash
   az feature register \
     --namespace Microsoft.Compute \
     --name UseStandardSecurityType
   # Aguarde o estado mostrar "Registered" (~1-2 minutos)
   az feature show \
     --namespace Microsoft.Compute \
     --name UseStandardSecurityType \
     --query properties.state
   ```
5. Ao conectar via Bastion, o GitHub requer um Personal Access Token para git clone (autenticação por senha desabilitada) — gere em: github.com → Settings → Developer settings → Personal access tokens → escopo repo

**Deploy:**
```bash
./deploy.sh
# → y → 4 (corp-lab)
# → SSH key dedicada gerada automaticamente em ~/.ssh/id_ed25519_llamapoc_corp
# → Pressione Enter para continuar
```

Outputs após o deployment:
- **IP privado do LlamaFirewall** — PyRIT se conecta aqui (ex.: `10.0.0.4`)
- **FQDN da VM PyRIT** — acesso Azure Bastion Developer SKU para sessões de red-team
- **FQDN da VM LlamaFirewall** — acesso Azure Bastion Developer SKU para admin/setup

**Configurar VM do LlamaFirewall:**
```bash
# Conecte via Bastion → terminal SSH abre no browser
# Clone o repositório (GitHub requer Personal Access Token — autenticação por senha desabilitada)
# Gere em: github.com → Settings → Developer settings → Personal access tokens
# Escopo: repo · Validade: 7 dias é suficiente
git clone https://<seu-usuario-github>:<SEU_PAT>@github.com/VinnieFreitas/llamafirewall-pyrit-poc.git
cd llamafirewall-pyrit-poc
chmod +x *.sh

# Execute o setup — detecta a localização do repositório automaticamente (sem scp necessário)
bash setup_vm.sh --profile lab 2>&1 | tee ~/setup.log

# Após o setup — copie as regras NOVA manualmente se necessário
sudo cp social_engineering_pt.nov /opt/llamafirewall/nova-rules-custom/
sudo systemctl restart llamafirewall
curl -sf http://localhost:8080/health  # deve mostrar NOVA(10rules)
```

**Configurar VM PyRIT:**
```bash
# Conecte via Bastion → terminal SSH abre no browser
git clone https://<seu-usuario-github>:<SEU_PAT>@github.com/VinnieFreitas/llamafirewall-pyrit-poc.git
cd llamafirewall-pyrit-poc
chmod +x *.sh

# Instalar PyRIT
sudo apt install python3.10-venv -y
./setup_pyrit.sh
source venv/bin/activate
```

**Executar PyRIT** — sem SSH tunnel, IP privado direto:
```bash
python3 pyrit_redteam.py \
  --endpoint http://<lf-ip-privado>:8080/v1 \
  --prompts-file custom_attacks.yaml
```

**Enviar para o Sentinel:**
```bash
python3 log_shipper.py --mode pyrit \
  --workspace-id <sentinel-workspace-id> \
  --workspace-key <sentinel-primary-key>
```

---

## Deployment Corp-Preprod

LlamaFirewall roda como container no cluster AKS. PyRIT roda como job GitLab CI.

**Arquitetura:**
```
GitLab CI (job PyRIT)
    │  --endpoint http://llamafirewall-svc:8080/v1
    ▼
AKS → LlamaFirewall pod (CPU) → Azure OpenAI (private endpoint)
```

**1. Build e push da imagem CPU:**
```bash
docker build -t <acr>.azurecr.io/llamafirewall-proxy:preprod \
  --build-arg HF_TOKEN=<hf-token> -f Dockerfile .
az acr login --name <acr>
docker push <acr>.azurecr.io/llamafirewall-proxy:preprod
```

**2. Deploy no AKS:**
```bash
kubectl create namespace llamafirewall
kubectl create secret generic llamafirewall-secrets \
  --namespace llamafirewall \
  --from-literal=HF_TOKEN=<hf-token> \
  --from-literal=SENTINEL_WORKSPACE_ID=<id> \
  --from-literal=SENTINEL_WORKSPACE_KEY=<chave>
kubectl apply -f k8s/llamafirewall-preprod.yaml
```

**3. Apontar o backend para o LlamaFirewall — uma mudança de variável de ambiente:**
```bash
kubectl set env deployment/backend \
  OPENAI_ENDPOINT=http://llamafirewall-svc.llamafirewall.svc.cluster.local:8080/v1 \
  -n <backend-namespace>
```

**4. Configurar variáveis GitLab CI** (Settings → CI/CD → Variables → marcar como Masked):

| Variável | Valor |
|---|---|
| `LLAMAFIREWALL_ENDPOINT` | `http://llamafirewall-svc.llamafirewall.svc.cluster.local:8080/v1` |
| `SENTINEL_WORKSPACE_ID` | ID do workspace Sentinel |
| `SENTINEL_WORKSPACE_KEY` | Primary key do Sentinel |

Atualize `YOUR_RUNNER_TAG_HERE` em `.gitlab-ci.yml` com a tag do runner confirmada pelo time de DevOps.

---

## Deployment Corp-Prod

Mesma arquitetura AKS do preprod — GPU node pool, profile production, canary probe a cada hora.

**Arquitetura:**
```
Usuário → EntraID → Angular SPA (AKS)
                          │
                     Backend (AKS)  [uma env var: OPENAI_ENDPOINT]
                          │
              LlamaFirewall pod (AKS — GPU node pool)
                          │
              Azure OpenAI (private endpoint, subscription diferente)

              Canary CronJob (AKS) → Sentinel LAW → Alertas
```

**1. Build e push da imagem GPU:**
```bash
docker build -t <acr>.azurecr.io/llamafirewall-proxy:prod \
  --build-arg HF_TOKEN=<hf-token> -f Dockerfile.gpu .
docker push <acr>.azurecr.io/llamafirewall-proxy:prod
```

**2. Deploy no GPU node pool** — adicione ao pod spec:
```yaml
resources:
  requests:
    nvidia.com/gpu: 1
  limits:
    nvidia.com/gpu: 1
```

**3. Deploy do canary CronJob** (executa automaticamente a cada hora):
```bash
kubectl apply -f k8s/canary-cronjob.yaml -n llamafirewall
```

Execução manual do canary a qualquer momento:
```bash
python3 canary_probe.py --mode canary \
  --endpoint http://llamafirewall-svc.llamafirewall.svc.cluster.local:8080/v1 \
  --workspace-id <sentinel-id> --workspace-key <sentinel-key>
```

**4. Alerta no Sentinel** — crie uma Analytics Rule:
```kusto
LlamaFirewallCanary_CL
| where TimeGenerated > ago(2h)
| where canary_run_type_s == "canary"
| summarize pass_rate = avg(pass_rate_d) by bin(TimeGenerated, 1h)
| where pass_rate < 90
```

---

## Gestão de Custos

```bash
# Deallocate a VM quando terminar (para a cobrança de computação, mantém o disco)
az vm deallocate --resource-group rg-llamapoc --name llamapoc-vm --no-wait

# Iniciar novamente quando necessário
az vm start --resource-group rg-llamapoc --name llamapoc-vm
```

**Custo por profile (uso leve ~20 hrs/mês ativo):**

| Profile | VM | Storage | LAW | Total |
|---|---|---|---|---|
| lab | ~$8 (B8ms) | ~$5 | Gratuito | **~$16/mês** |
| preprod | ~$15 (D8s_v3) | ~$8 | Gratuito | **~$28/mês** |
| production | ~$32 (D16s_v3) | ~$15 | ~$5 | **~$55/mês** |
| corp-lab | ~$30 (NC4as+B2ms) | ~$10 | Gratuito | **~$45/mês** |

> Production e corp-prod não possuem auto-shutdown — lembre-se de fazer deallocate manualmente.

---

## Teardown

```bash
# 1. Fechar SSH tunnel (profiles home)
kill $(cat /tmp/llamapoc_tunnel.pid)

# 2. Deallocate VM
az vm deallocate --resource-group rg-llamapoc --name llamapoc-vm --no-wait
```

> ⚠️ **Deallocate ≠ Shutdown.** `sudo shutdown` mantém a cobrança. Use sempre `az vm deallocate`.

**Retomar:**
```bash
az vm start --resource-group rg-llamapoc --name llamapoc-vm
./test_tunnel.sh azureuser@llamapoc-llama.eastus.cloudapp.azure.com
# Aqueça os modelos antes de executar o PyRIT
ssh azureuser@llamapoc-llama.eastus.cloudapp.azure.com << 'EOF'
curl -sf http://localhost:11434/api/generate \
  -d '{"model":"llama-guard3:8b","prompt":"hello","stream":false}' > /dev/null && echo "llama-guard3 warm"
curl -sf http://localhost:11434/api/generate \
  -d '{"model":"phi3:mini","prompt":"hello","stream":false}' > /dev/null && echo "phi3:mini warm"
EOF
```

**Destruição completa:**
```bash
./teardown.sh
```

---

## Roadmap de Hardening para Produção

**Implementado:**

| ✅ | Scanner | O que detecta |
|---|---|---|
| ✅ | PromptGuard 2 | Sintaxe de injection, padrões de jailbreak |
| ✅ (opcional) | PerplexityFilter | Sufixos adversariais gerados por gradient descent |
| ✅ | HiddenASCII | Texto BiDi, caracteres invisíveis, encoding tricks |
| ✅ | Regex + CustomPatterns | XSS, SQL, credenciais, abuso de tools |
| ✅ | LlamaGuard 3:8B | Engenharia social, segurança de conteúdo |
| ✅ | NOVA (keyword+semantic) | Armadilhas lógicas, injeção de tools, síntese de bioarmas |
| ✅ | CrescendoTracker | Escalada multi-turn, padrão Crescendo (estado em memória) |
| ✅ (preprod+prod) | Output scanning (LlamaGuard3) | Conteúdo nocivo nas respostas do LLM |
| ✅ (preprod+prod) | CodeShield | Código malicioso nas respostas |
| ✅ (preprod+prod) | Output sensitive data regex | CPF, CNPJ, credenciais, chaves nas respostas |

**Roadmap:**

| Gap | Observações | Correção |
|---|---|---|
| NOVA LLM tier | Desabilitado — phi3:mini causava falsos positivos | Classificador de segurança dedicado na GPU |
| Inferência GPU | CPU média ~23s/prompt | NC-series T4 → ~1-2s/prompt (implementado em corp-lab/prod) |
| Kubernetes manifests | Pasta k8s/ referenciada mas ainda não commitada | Adicionar YAMLs de Deployment, Service, ConfigMap, CronJob |
| GitLab runner tag | Placeholder `YOUR_RUNNER_TAG_HERE` em `.gitlab-ci.yml` | Atualizar quando o time de DevOps confirmar o tipo do runner |

---

## Notas de Segurança

- `deploy-outputs.json` contém a primary key do LAW — **nunca commite este arquivo**
- Profiles home: NSG permite SSH de qualquer IP — restrinja `sourceAddressPrefix` em `main.bicep` para uso em produção
- Corp profiles: NSG restringe SSH ao service tag `VirtualNetwork` — acessível apenas via Azure Bastion
- O proxy LlamaFirewall faz bind em `127.0.0.1` nas VMs — acessível apenas via SSH tunnel ou VNet interna
- O token HuggingFace é injetado no env do systemd / Kubernetes Secret — nunca armazenado em arquivos de configuração
- A SSH key corp (`id_ed25519_llamapoc_corp`) é separada da chave pessoal — nunca reutilize chaves pessoais em ambientes corporativos
