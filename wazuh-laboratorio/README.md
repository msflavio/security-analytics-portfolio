# Wazuh Laboratório - SIEM Open Source

**Data:** 13/03/2026  
**Autor:** Flávio  
**Objetivo:** Explorar e documentar os recursos do Wazuh como solução SIEM open source, incluindo criação de regras customizadas e alertas.

---

## 📌 Sobre o Projeto

Este repositório documenta os laboratórios realizados com o **Wazuh**, uma plataforma de segurança open source para detecção de ameaças, monitoramento de integridade e resposta a incidentes.

Foram criadas **4 regras customizadas** para detecção de:
- Força bruta SSH
- SQL Injection
- IOCs (User-Agent sqlmap e usuário devops)

---

## 🛠️ Configuração do Ambiente

### Componentes
- **Wazuh Manager** (servidor)
- **Wazuh Indexer** (armazenamento)
- **Wazuh Dashboard** (interface web)
- **Wazuh Agent** (endpoints)

### Instalação
`ash
# Clonar repositório
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.3
cd wazuh-docker/single-node

# Gerar certificados
docker-compose -f generate-indexer-certs.yml run --rm generator

# Iniciar containers
docker-compose up -d
Acessar dashboard: https://<IP>:443 (usuário: admin, senha: SecretPassword)

📋 Regras Customizadas Criadas
Todas as regras foram adicionadas ao arquivo rules_custom.xml:

https://assets/wazuh-regras-customizadas-4-regras.jpg

Regra 600102 - Força Bruta SSH
xml
<rule id="600102" level="10" frequency="5" timeframe="120" ignore="60">
  <if_matched_sid>5710</if_matched_sid>
  <same_srcip/>
  <description>Brute Force SSH</description>
</rule>
https://assets/wazuh-rule-brute-force-ssh.jpg

Regra 600103 - SQL Injection
xml
<rule id="600103" level="10">
  <if_sid>31100</if_sid>
  <url>=select%20|select+|insert%20|%20from%20|%20where%20|union%20|</url>
  <url>union+|where+|null,null|xp_cmdshell</url>
  <description>Possivel SQL injection identified</description>
</rule>
Regra 600104 - IOC User-Agent sqlmap
xml
<rule id="600104" level="10">
  <if_sid>31100</if_sid>
  <match>sqlmap/1.7.10#stable</match>
  <description>IOC Detectado - UserAgent - Incidente XPT</description>
</rule>
Regra 600105 - IOC Usuário devops
xml
<rule id="600105" level="7">
  <if_sid>5700,5710,5715,5716,5763</if_sid>
  <user>devops</user>
  <description>IOC Detectado - User devops - Incidente XPT</description>
</rule>
https://assets/wazuh-regras-customizadas-duas.jpg
https://assets/wazuh-regras-customizadas-completas.jpg

🚨 Alertas Disparados
1. Força Bruta SSH (600102)
A regra detectou múltiplas tentativas de login SSH falhas:

https://assets/wazuh-alerta-600102-disparado.jpg

2. SQL Injection (600103)
Detecção de padrões de SQL Injection em logs web:

https://assets/wazuh-alerta-600103-sql-injection.jpg

3. IOC sqlmap (600104)
Detecção do User-Agent da ferramenta sqlmap:

https://assets/wazuh-alerta-600104-ioc-sqlmap.jpg

4. IOC devops (600105)
Detecção do usuário devops em logs SSH:

https://assets/wazuh-alerta-600105-ioc-devops.jpg

✅ Resumo dos Resultados
ID    Tipo    Descrição    Level    Status
600102    Força Bruta    Brute Force SSH    10    ✅
600103    SQL Injection    Possível SQL injection    10    ✅
600104    IOC    User-Agent sqlmap    10    ✅
600105    IOC    Usuário devops    7    ✅
📊 Estatísticas
4 regras customizadas criadas

4 alertas disparados com sucesso

8 prints documentando todo o processo

1 laboratório completo de SIEM open source

📂 Estrutura de Arquivos
text
wazuh-laboratorio/
├── README.md
└── assets/
    ├── wazuh-rule-brute-force-ssh.jpg
    ├── wazuh-regras-customizadas-duas.jpg
    ├── wazuh-regras-customizadas-completas.jpg
    ├── wazuh-regras-customizadas-4-regras.jpg
    ├── wazuh-alerta-600102-disparado.jpg
    ├── wazuh-alerta-600103-sql-injection.jpg
    ├── wazuh-alerta-600104-ioc-sqlmap.jpg
    └── wazuh-alerta-600105-ioc-devops.jpg
🔗 Links Úteis
Documentação Oficial Wazuh

Repositório GitHub Wazuh

Wazuh Docker Deployment

✅ Conclusão
O laboratório demonstrou com sucesso a capacidade do Wazuh para:

Criar regras customizadas de detecção

Identificar ataques de força bruta SSH

Detectar SQL Injection em logs web

Monitorar IOCs específicos (User-Agent e usuários)

Gerar alertas em tempo real

Total de prints no portfólio: 8
