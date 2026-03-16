# Sigma Rules - Conversão de Regras de Detecção

**Data:** 16/03/2026  
**Autor:** Flávio  
**Objetivo:** Explorar o formato Sigma para criação e conversão de regras de detecção entre diferentes SIEMs.

---

## 🔹 O que são Sigma Rules?

Sigma é um formato genérico e de código aberto para regras de detecção, permitindo que uma única regra seja convertida para diferentes SIEMs (Splunk, Wazuh, Elastic, QRadar, etc.).

> "Sigma é para logs o que Snort é para tráfego de rede e YARA é para arquivos."

---

## 🔹 Regras Desenvolvidas

### 1. Força Bruta SSH (simples)
**ID:** 2617e7ed-adb7-40ba-b0f3-8f9945fee601  
**Level:** high

![Regra Sigma - SSH Bruta](assets/sigma-regra-ssh-bruta.jpg)

`yaml
title: Brute Force SSH Detectado
id: 2617e7ed-adb7-40ba-b0f3-8f9945fee601
status: stable
description: Identifica falhas de login via SSH no ambiente Linux.
author: Flavio Marçal Santos
date: 2026/03/16
logsource:
  product: linux
  service: ssh
detection:
  selection:
    event.type: authentication_failure
  condition: selection
falsepositives:
  - Erro de digitação de usuários legítimos
level: high
Conversão para Splunk:

spl
event.type="authentication_failure"
2. SQL Injection
ID: 2617e7ed-adb7-40ba-b0f3-8f9945fe6c02
Level: high

https://assets/sigma-regra-sql-injection.jpg

yaml
title: Possível SQL Injection Identificado
id: 2617e7ed-adb7-40ba-b0f3-8f9945fe6c02
status: stable
description: Detecta palavras-chave de SQL (select, union, where) em requisições HTTP.
author: Flavio Marçal Santos
date: 2026/03/16
logsource:
  category: webserver
detection:
  selection:
    url|contains:
    - 'select'
    - 'union'
    - 'where'
    - 'insert'
    - 'null'
    - 'xp_cmdshell'
  condition: selection
falsepositives:
  - Consultas legítimas em sistemas de busca internos
level: high
Conversão para Splunk:

spl
url IN ("select*", "union*", "where*", "insert*", "null*", "xp_cmdshell*")
3. IOC SQLMap
ID: 2617e7ed-adb7-40ba-b0f3-8f9945fe6c03
Level: critical

https://assets/sigma-regra-ioc-sqlmap.jpg

yaml
title: IOC Detectado - Ferramenta SQLMap
id: 2617e7ed-adb7-40ba-b0f3-8f9945fe6c03
status: stable
description: Detecta o uso da ferramenta sqlmap através do User-Agent.
author: Flavio Marçal Santos
date: 2026/03/16
logsource:
  category: webserver
detection:
  selection:
    http.useragent|contains: 'sqlmap/1.7.10#stable'
  condition: selection
falsepositives:
  - Atividades de Pentest autorizadas
level: critical
Conversão para Splunk:

spl
http.useragent="*sqlmap/1.7.10#stable"
4. IOC Usuário devops
ID: 2617e7ed-adb7-40ba-b0f3-8f9945fe6001
Level: high

https://assets/sigma-regra-ioc-devops.jpg

yaml
title: IOC Detectado - Usuário - Incidente XPT
id: 2617e7ed-adb7-40ba-b0f3-8f9945fe6001
status: stable
description: Identifica tentativas de acesso com o usuário 'devops' associado ao incidente XPT.
author: Flavio Marçal Santos
date: 2026/03/16
logsource:
  category: authentication
detection:
  selection:
    user_name: 'devops'
  condition: selection
falsepositives:
  - Ações legítimas de administração (se o usuário for reabilitado)
level: high
Conversão para Splunk:

spl
user_name="devops"
5. Correlação - Força Bruta SSH
ID: 5513deaf-f49a-46c2-a6c8-3f111b5c0003
Level: medium

https://assets/sigma-regra-correlacao-ssh.jpg

yaml
title: Brute Force SSH  
id: 5513deaf-f49a-46c2-a6c8-3f111b5c0003  
status: experimental  
description: Esta regra aciona quando um ataque de força bruta é detectado no SSH  
author: Flavio Marçal Santos  
date: 2026/03/16  
correlation:  
    type: event_count  
    rules:  
    - wrong_password_ssh  
group-by:  
    - host  
    - user  
timespan: 15m  
condition:  
    get: 10  
level: medium  

---
title: Erro de senha - SSH  
name: wrong_password_ssh  
id: 5513deaf-f49a-46c2-a6c8-3f111b5c0002  
status: stable  
description: Está regra aciona quando um erro de senha no SSH é detectado  
author: Flavio Marçal Santos  
date: 2026/03/16  
logsource:  
    product: linux  
    service: ssh  
detection:  
    selection:  
    message|contains: 'Failed password'  
    condition: selection  
level: informational
🔹 Conversões Realizadas
Regra    ID    Level    Splunk
Força Bruta SSH (simples)    2617e7ed...601    high    ✅
SQL Injection    2617e7ed...c02    high    ✅
IOC SQLMap    2617e7ed...c03    critical    ✅
IOC devops    2617e7ed...001    high    ✅
Correlação SSH    5513deaf...003    medium    ✅
✅ Resumo
5 regras Sigma criadas

5 conversões para Splunk realizadas

5 prints documentando o processo

📂 Estrutura de Arquivos
text
sigma-rules-conversao/
├── README.md
└── assets/
    ├── sigma-regra-ssh-bruta.jpg
    ├── sigma-regra-sql-injection.jpg
    ├── sigma-regra-ioc-sqlmap.jpg
    ├── sigma-regra-ioc-devops.jpg
    └── sigma-regra-correlacao-ssh.jpg
📌 Anexos
Todos os prints estão na pasta assets/.
