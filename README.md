<img src="https://github.com/secbras/xsstorm/blob/main/xsstorm.png?raw=true" alt="XSStorm" width="300">

# ⚡ XSStorm – Advanced XSS Scanner

XSStorm é um scanner de vulnerabilidades XSS (Cross-Site Scripting) de alta performance que combina técnicas de análise estática e dinâmica para identificar pontos vulneráveis em aplicações web.

---

## 🌪️ Funcionalidades Principais

- **Varredura Profunda** de formulários HTML tradicionais e dinâmicos (JavaScript)
- **Detecção Contextual** de reflexão de payloads (HTML, JavaScript, Atributos)
- **Biblioteca de Payloads** com 100+ vetores XSS categorizados
- **Análise de Sanitização** para identificar filtros ineficientes
- **Multi-threading** para execução acelerada de testes
- **Relatório Detalhado** com classificação de vulnerabilidades
- **Suporte** a formulários em iframes e AJAX

---

## 🛠️ Requisitos Técnicos

### 📋 Pré-requisitos
- Python 3.8+
- Pipenv (recomendado)

### 📦 Dependências
```bash
pip install requests beautifulsoup4 tqdm urllib3
```

---

## ⚙️ Instalação Rápida
```bash
git clone https://github.com/seu-usuario/xsstorm.git
cd xsstorm
pip install -r requirements.txt
```

---

## 🚀 Como Usar

### 🔹 Modo Básico
```bash
python xsstorm.py
```
(O script solicitará a URL alvo)

### 🔸 Opções Avançadas
```bash
python xsstorm.py --url https://alvo.com --threads 20 --timeout 30
```

**Parâmetros:**

- `--url`: URL alvo (opcional)  
- `--threads`: Número de threads paralelas (padrão: 10)  
- `--timeout`: Tempo máximo por requisição (segundos)  
- `--verbose`: Modo detalhado  

---

## 🔍 Metodologia de Teste

**Mapeamento de Superfície:**
- Identificação de todos os formulários
- Detecção de formulários dinâmicos via JavaScript
- Análise de iframes embutidos

**Injeção de Payloads:**
- Teste de 100+ vetores XSS categorizados
- Verificação de reflexão em múltiplos contextos
- Análise de mecanismos de sanitização

**Validação:**
- Confirmação de contexto de execução
- Classificação de vulnerabilidades
- Geração de relatório consolidado

---

## 📊 Saída de Exemplo
```plaintext
[+] Formulário encontrado em /contact.php
[!] Vulnerabilidade XSS detectada:
    Payload: <svg/onload=alert(1)>
    Contexto: Atributo HTML sem sanitização
    Campo: user_comments
```

---

## ⚠️ Aviso Legal

Este software deve ser utilizado apenas em testes de segurança autorizados.  
Qualquer uso não autorizado em sistemas sem permissão explícita é estritamente proibido.  
O desenvolvedor não se responsabiliza pelo uso indevido desta ferramenta.

---

## 🤝 Como Contribuir

- Reporte issues no GitHub  
- Envie pull requests com melhorias  
- Proponha novos payloads de teste  
- Ajude a melhorar a documentação  

---

## 📄 Licença

Distribuído sob licença MIT. Veja `LICENSE` para mais informações.

---
