import os
import sys
import json
import requests
from urllib.parse import urljoin

# ==============================================================================
# SCRIPT DE DIAGNOSTICO COMPLETO - Bitrix24 Foto Downloader
# ==============================================================================
# Use este script para testar se as chaves, webhooks e seu PHP estao funcionando.
# ==============================================================================

# 1. Coloque sua URL do Webhook do Bitrix24 aqui para testar a conexao com ele
WEBHOOK_BITRIX = "https://SUA_EMPRESA.bitrix24.com.br/rest/1/SEU_TOKEN/"

# 2. Coloque a URL do seu logger PHP aqui (a mesma que esta no app_gui.py)
URL_LOGGER_PHP = "https://labspessoa.com.br/logger.php"

# 3. Coloque o Token de seguranca do PHP (o mesmo que esta no app_gui.py)
TOKEN_LOGGER_PHP = "BX24_LOG_77A8F932D939"


def print_title(text):
    print(f"\n{'='*60}\n{text}\n{'='*60}")

def teste_sistema():
    print_title("1. DIAGNOSTICO DE SISTEMA")
    print(f"[*] Python Version: {sys.version.split()[0]}")
    print(f"[*] Sistema Operacional: {os.name}")
    print(f"[*] Diretorio Atual: {os.getcwd()}")
    
    # Teste de permissao de escrita
    teste_file = "teste_escrita.tmp"
    try:
        with open(teste_file, "w") as f:
            f.write("OK")
        os.remove(teste_file)
        print("[+] Permissoes de escrita na pasta atual: OK")
    except Exception as e:
        print(f"[-] ERRO: Sem permissao de escrita. Detalhes: {e}")

def teste_bitrix():
    print_title("2. DIAGNOSTICO BITRIX24")
    if "SUA_EMPRESA" in WEBHOOK_BITRIX:
        print("[!] PULO: URL do Webhook nao configurada no script de teste.")
        return

    print(f"[*] Conectando em: {WEBHOOK_BITRIX[:40]}...")
    url_users = urljoin(WEBHOOK_BITRIX, "user.get.json")
    try:
        resp = requests.get(url_users, timeout=10)
        if resp.status_code == 200:
            dados = resp.json()
            if "result" in dados:
                total = len(dados["result"])
                print(f"[+] SUCESSO: Conexao com Bitrix24 OK! Recebidos {total} usuarios (na primeira pagina).")
            else:
                print("[-] ERRO: Resposta inesperada do Bitrix. Verifique as permissoes do Webhook.")
        elif resp.status_code in [401, 403]:
            print(f"[-] ERRO: Acesso negado ({resp.status_code}). Token do Webhook pode ser invalido ou expirou.")
        else:
            print(f"[-] ERRO HTTP {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[-] ERRO FATAL de Conexao: {e}")

def teste_php_logger():
    print_title("3. DIAGNOSTICO LOGGER PHP (cPanel)")
    if not URL_LOGGER_PHP or "labspessoa" not in URL_LOGGER_PHP:
        # Tenta pegar se o usuario so esqueceu de mudar mas ja testamos a logica
        pass
    
    print(f"[*] Enviando teste HTTP POST para: {URL_LOGGER_PHP}")
    payload = {
        "nome": "TESTE DE DIAGNOSTICO",
        "departamento": "TI",
        "maquina": os.environ.get("COMPUTERNAME", "Desconhecida"),
        "acao": "TESTE_CONEXAO",
        "detalhes": "Validando o funcionamento do endpoint PHP."
    }
    headers = {
        "X-Audit-Token": TOKEN_LOGGER_PHP,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        resp = requests.post(URL_LOGGER_PHP, json=payload, headers=headers, timeout=10)
        if resp.status_code in [200, 201]:
            print("[+] SUCESSO: Log registrado no seu cPanel com sucesso!")
            try:
                js = resp.json()
                print(f"    Resposta do Servidor: {js.get('message', 'OK')}")
            except:
                pass
        elif resp.status_code == 401:
            print("[-] ERRO DE AUTENTICACAO: O 'X-Audit-Token' enviado não é igual ao 'SECRET_TOKEN' no logger.php.")
            print(f"    Token Enviado: {TOKEN_LOGGER_PHP}")
        elif resp.status_code == 413:
            print("[-] ERRO DE PAYLOAD: O JSON enviado é maior que o limite permitido no logger.php.")
        else:
            print(f"[-] ERRO HTTP {resp.status_code}: Pode ser que o logger.php nao esteja acessivel ou tenha erros de PHP.")
            print(f"    HTML Retornado: {resp.text[:200]}")
    except Exception as e:
        print(f"[-] ERRO DE REDE ao contatar o PHP: {e}")


if __name__ == "__main__":
    teste_sistema()
    teste_bitrix()
    teste_php_logger()
    print("\n" + "="*60)
    print("FIM DO DIAGNOSTICO")
    print("="*60 + "\n")
