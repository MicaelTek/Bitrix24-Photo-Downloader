import os
import sys
import json
import requests
from urllib.parse import urljoin
from dotenv import load_dotenv

# ==============================================================================
# SCRIPT DE DIAGNOSTICO COMPLETO - Bitrix24 Foto Downloader
# ==============================================================================
# Use este script para testar se as chaves, webhooks e seu PHP estao funcionando.
# ==============================================================================

load_dotenv()

# 1. URL do Webhook do Bitrix24
WEBHOOK_BITRIX = os.getenv("API_WEBHOOK_URL", "")

# 2. URL do logger PHP (Opcional)
URL_LOGGER_PHP = os.getenv("API_LOGGER_URL", "")

# 3. Token de seguranca do PHP (Opcional)
TOKEN_LOGGER_PHP = os.getenv("API_LOGGER_TOKEN", "")

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
    if not WEBHOOK_BITRIX:
        print("[-] ERRO FATAL: URL do Webhook nao configurada no .env (API_WEBHOOK_URL).")
        sys.exit(1)

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
                print("[-] ERRO FATAL: Resposta inesperada do Bitrix. Verifique as permissoes do Webhook.")
                sys.exit(1)
        elif resp.status_code in [401, 403]:
            print(f"[-] ERRO FATAL: Acesso negado ({resp.status_code}). Token do Webhook pode ser invalido ou expirou.")
            sys.exit(1)
        else:
            print(f"[-] ERRO FATAL HTTP {resp.status_code}: {resp.text}")
            sys.exit(1)
    except Exception as e:
        print(f"[-] ERRO FATAL de Conexao: {e}")
        sys.exit(1)

def teste_php_logger():
    print_title("3. DIAGNOSTICO LOGGER PHP (cPanel) [OPCIONAL]")
    if not URL_LOGGER_PHP:
        print("[!] AVISO: URL_LOGGER_PHP nao configurada no .env. A auditoria remota estara desativada.")
        return
    
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
