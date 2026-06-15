# 🛡️ Security Analytics & Detection Engineering Portfolio

**Autor:** Flávio Marçal  
**LinkedIn:** [www.linkedin.com/in/msflavio](https://www.linkedin.com/in/msflavio)

Bem-vindo ao meu portfólio de Engenharia de Detecção e Análise de Segurança. Este repositório reúne projetos práticos focados em análise forense de logs, correlação de eventos em SIEM (Splunk), monitoramento de endpoints (Wazuh) e desenvolvimento de regras de detecção universais utilizando o framework Sigma.

---

## 🎯 Cenário Resumido dos Projetos
Os projetos simulam um ambiente corporativo sob um ataque multifásico. O objetivo foi rastrear a atividade maliciosa desde o vetor inicial de acesso até as ações nos objetivos, desdobrando a investigação em alertas de produção e inteligência de ameaças.

### 🗺️ Mapeamento MITRE ATT&CK Coberto:
* **Initial Access:** T1190 - Exploit Public-Facing Application (SQL Injection)
* **Credential Access:** T1110 - Brute Force (SSH Brute Force)
* **Command and Control:** T1571 - Non-Standard Port / User-Agent maliciosos (sqlmap)

---

## 📊 Projetos e Estrutura

### 🔬 1. Investigação de Ataque Multifásico (Múltiplas Fontes)
**Pasta:** [`investigacao-ataque-multiplas-fontes`](investigacao-ataque-multiplas-fontes)
Análise forense e reconstrução da linha do tempo de um incidente complexo através da correlação de logs de diferentes camadas da infraestrutura.
* **Fontes de Logs Analisadas:** Firewall, Proxy, DHCP, Active Directory, Antivírus, DNS, IDS e File Server.
* **Entregáveis:** Linha do tempo detalhada do ataque, identificação de Indicadores de Comprometimento (IOCs) e contenção lógica.
* **Evidências:** 📸 16 prints documentando o passo a passo da investigação.

### 🔥 2. Engenharia de Detecção no Splunk (Alertas Pós-Incidente)
**Pasta:** [`prevencao-alertas-pos-incidente`](prevencao-alertas-pos-incidente)
Transformação dos achados da investigação em regras de detecção contínua dentro do Splunk (SPL), visando mitigar futuros ataques similares.
* **Casos de Uso Implementados:** * Detecção de força bruta SSH por volumetria.
  * Identificação de padrões de injeção SQL em logs de aplicação.
  * Alertas em tempo real para IOCs específicos (User-Agent `sqlmap` e criação do usuário anômalo `devops`).
* **Evidências:** 📸 14 prints das queries SPL e painéis de alertas.

### 🐺 3. Wazuh - Regras Customizadas e Monitoramento de Endpoints
**Pasta:** [`wazuh-laboratorio`](wazuh-laboratorio)
Configuração do Wazuh (EDR/XDR) para detecção a nível de host/endpoint, criando decoders e regras customizadas.
* **Regras Desenvolvidas:**
  * `600102` - SSH Brute Force Detection
  * `600103` - SQL Injection Attempt via Web Logs
  * `600104` - Malicious User-Agent Detection (sqlmap)
  * `600105` - Unauthorized User Creation (`devops`)
* **Evidências:** 📸 8 prints do laboratório e disparo dos alertas no painel do Wazuh.

### 📜 4. Sigma Rules - Detecção como Código (Detection as Code)
**Pasta:** [`sigma-rules-conversao`](sigma-rules-conversao)
Padronização das detecções utilizando o formato universal Sigma, permitindo que as regras criadas sejam portáveis para qualquer SIEM do mercado.
* **Desenvolvimento:** 5 regras completas em formato YAML escritas do zero.
* **Conversão:** Demonstração prática da tradução automatizada das regras Sigma para sintaxe nativa do Splunk.
* **Diferencial:** Implementation de regras de correlação avançadas utilizando janelas de tempo (*timespan*).
* **Evidências:** 📸 5 prints dos arquivos e validação na ferramenta de conversão.

---

## 🛠️ Hard Skills Demonstradas

* **SIEM & Analytics:** Splunk (SPL Query Optimization, Alerting).
* **XDR/EDR:** Wazuh (Custom Rules Development, Log Decoding).
* **Detection as Code:** Regras Sigma (YAML, Sigma CLI/Uncoder).
* **Análise Forense:** Triagem e correlação de Windows Event Logs, Sysmon, DNS, Firewalls e Proxies.
* **Threat Intelligence:** Extração, categorização e bloqueio de IOCs.

---

## 📁 Projetos de Governança, Risco e Conformidade (GRC)

Além da engenharia de detecção ativa, também desenvolvo análises estratégicas voltadas para a maturidade de segurança corporativa e conformidade regulatória.

### 🏢 Avaliação de Riscos e Auditoria baseada no NIST CSF — Botium Toys
Realizei uma auditoria completa na infraestrutura de uma empresa de e-commerce para identificar lacunas críticas de segurança frente às normas internacionais **PCI DSS** e **RGPD**.

* **Risco Crítico:** Ausência de criptografia em dados de cartões de crédito armazenados localmente e falta de controle de acesso (Princípio do Menor Privilégio).
* **Pontuação de Risco Organizacional:** 8 / 10 (Alto Risco).

👉 [**Clique aqui para acessar a pasta com o Relatório Detalhado e Anexos Técnicos deste projeto**](./01-auditoria-botium-toys/)

---

## 📁 Estrutura do Repositório
```text
security-analytics-portfolio/
├── 01-auditoria-botium-toys/             # Relatório GRC e PDFs de conformidade
├── investigacao-ataque-multiplas-fontes/   # Análise forense & timeline
├── prevencao-alertas-pos-incidente/         # Queries SPL e alertas Splunk
├── wazuh-laboratorio/                       # Arquivos XML de regras do Wazuh
└── sigma-rules-conversao/                   # Regras .yml Sigma e traduções