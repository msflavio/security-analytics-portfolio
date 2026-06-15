\# 🏢 Avaliação de Riscos e Auditoria de Conformidade: Botium Toys



Este projeto apresenta a execução de uma auditoria de segurança da informação e avaliação de riscos realizada para a empresa de comércio eletrônico \*\*Botium Toys\*\*. A análise foi estruturada utilizando como base as diretrizes do framework \*\*NIST CSF\*\* (Cybersecurity Framework) e as exigências regulatórias das normas \*\*PCI DSS\*\* e \*\*RGPD\*\*.



O objetivo desta avaliação foi mapear os ativos da organização, preencher uma lista de verificação de conformidade e propor os controles de segurança necessários para mitigar vulnerabilidades e elevar a maturidade de proteção dos dados.



\---



\## 🎯 Escopo e Objetivos da Auditoria



\* \*\*Escopo:\*\* Todo o programa de segurança da Botium Toys, englobando os ativos gerenciados pelo departamento de TI (equipamentos locais, dispositivos de usuários finais, sistemas de comércio eletrônico, bancos de dados e sistemas legados).

\* \*\*Objetivos:\*\* Avaliar os ativos existentes e preencher uma lista de verificação de controles para determinar quais práticas de conformidade precisam ser implementadas para aprimorar a postura de segurança da empresa.



\---



\## 📊 Lista de Verificação de Controles (Gap Analysis)



Abaixo está o diagnóstico detalhado dos controles de segurança inspecionados, classificando-os entre ativos (Sim) ou ausentes (Não) na infraestrutura atual da empresa:



| Controle de Segurança | Implementado? | Diagnóstico Técnico / Impacto no Negócio |

| :--- | :---: | :--- |

| \*\*Princípio do Menor Privilégio\*\* | ❌ Não | Todos os funcionários possuem acesso irrestrito aos dados internos, incluindo dados de cartões de crédito e informações pessoais (PII) de clientes. |

| \*\*Criptografia de Dados\*\* | ❌ Não | Dados financeiros e informações de cartões de crédito são aceitos e armazenados localmente sem qualquer tipo de criptografia, violando o PCI DSS. |

| \*\*Plano de Recuperação de Desastres (DRP)\*\* | ❌ Não | Não existem planos de continuidade de negócios ou rotinas de backup para dados críticos implementados. |

| \*\*Segregação de Funções\*\* | ❌ Não | Controles de acesso inadequados. O CEO centraliza tanto as operações diárias quanto o gerenciamento da folha de pagamento, gerando risco de fraude. |

| \*\*Firewall de Borda\*\* |  Sim | O departamento de TI possui um firewall ativo que bloqueia o tráfego de rede com base em regras de segurança adequadamente definidas. |

| \*\*Sistema de Detecção de Intrusão (IDS)\*\* | ❌ Não | A rede interna não possui um IDS instalado, limitando a capacidade de identificar intrusões ou anomalias em tempo real. |

| \*\*Software Antivírus\*\* |  Sim | Proteção de endpoint ativa, instalada e monitorada regularmente nas estações de trabalho dos funcionários. |

| \*\*Política e Complexidade de Senhas\*\* | ❌ Não | Os requisitos de senhas são nominais/mínimos e não forçam critérios modernos de complexidade (como caracteres especiais e tamanho seguro). |

| \*\*Gerenciamento Centralizado de Senhas\*\* | ❌ Não | Ausência de um cofre ou gerenciador centralizado, afetando a produtividade da equipe de TI com chamados frequentes para redefinições de credenciais. |

| \*\*Segurança Física (CFTV e Trancas)\*\* |  Sim | As instalações físicas (loja, escritórios e depósito) possuem fechaduras suficientes, sistema de videovigilância por CFTV ativo e prevenção de incêndios operacional. |



\---



\## 🚨 Avaliação de Risco e Impacto de Conformidade



\* \*\*Pontuação de Risco Atual:\*\* \*\*8 / 10\*\* (Risco Consideravelmente Alto).

\* \*\*Análise de Impacto:\*\* O e-commerce da Botium Toys aceita, processa e armazena dados confidenciais e financeiros sem criptografia. Devido à falta de controle de acesso, qualquer usuário interno pode visualizar essas informações de titulares de cartões. Esse cenário gera uma não-conformidade crítica com as regulamentações internacionais \*\*PCI DSS\*\* e \*\*RGPD\*\*, deixando a empresa exposta a vazamentos massivos e sanções legais severas.



\---



\## 🛡️ Recomendações Tecnológicas Propostas



Para sanar as lacunas de conformidade e mitigar os riscos críticos avaliados, as seguintes ações prioritárias foram recomendadas à gestão de TI:



1\. \*\*Privilégio Mínimo e Segregação:\*\* Restringir o acesso a dados PII e financeiros, garantindo que apenas usuários estritamente autorizados para suas funções operacionais manipulem essas informações.

2\. \*\*Criptografia Forte (AES-256):\*\* Implementar rotinas de cifragem para garantir a confidencialidade das transações e dados armazenados localmente no banco de dados.

3\. \*\*Continuidade e Backups:\*\* Estabelecer um plano formal de recuperação de desastres (DRP) e configurar rotinas automatizadas de backups de dados críticos fora do ambiente local.

4\. \*\*Visibilidade com IDS:\*\* Adquirir e configure um Sistema de Detecção de Intrusão (IDS) para monitorar e alertar sobre atividades anômalas ou suspeitas na rede periférica.

