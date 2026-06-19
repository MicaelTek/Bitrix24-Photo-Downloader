"""
=============================================================================
Bitrix24 - Downloader de Fotos (Interface Grafica v2.1 — Edicao Segura)
=============================================================================
Seguranca implementada:
  [1] Autenticacao por senha com hash PBKDF2-SHA256 + salt aleatorio
  [2] Lockout de 60s apos 3 tentativas erradas
  [3] Webhook URL criptografado em disco com Fernet (AES-256)
  [4] Log de auditoria (auditoria.log) registrando todos os acessos

Requisitos:
  pip install requests python-dotenv customtkinter Pillow cryptography

Para gerar o .exe:
  Execute build_exe.bat
=============================================================================
"""

import base64
import hashlib
import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import traceback

sys.stderr = open("crash.log", "a", encoding="utf-8")
sys.stdout = sys.stderr

from datetime import datetime, timedelta
from pathlib import Path
from queue import Empty, Queue
from urllib.parse import urljoin, urlparse

from dotenv import load_dotenv
import customtkinter as ctk
import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─────────────────────────────────────────────────────────────────────────────
# Variaveis de Ambiente (.env)
# ─────────────────────────────────────────────────────────────────────────────
# O PyInstaller embute esse arquivo no executável se configurado,
# ou os valores ficarão fixos na memória durante o build dependendo do setup.
load_dotenv()

API_WEBHOOK_URL = os.getenv("API_WEBHOOK_URL", "")
API_LOGGER_URL = os.getenv("API_LOGGER_URL", "")
API_LOGGER_TOKEN = os.getenv("API_LOGGER_TOKEN", "")

# ─────────────────────────────────────────────────────────────────────────────
# Tema Visual
# ─────────────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

ACCENT = "#3F3F46"
ACCENT_HOVER = "#52525B"
ERROR_CLR = "#EF4444"
BG_DARK = "#09090B"
BG_CARD = "#18181B"
BG_INPUT = "#27272A"
TEXT_PRIMARY = "#FAFAFA"
TEXT_SECONDARY = "#A1A1AA"
BORDER_COLOR = "#3F3F46"
TEXT_ON_ACCENT = "#FAFAFA"

# ─────────────────────────────────────────────────────────────────────────────
# Constantes de Operacao
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR = Path("C:/Bitrix24Fotos")
PASTA_DESTINO = BASE_DIR / "fotos_usuarios_bitrix"
ARQUIVO_INDICE = PASTA_DESTINO / "indice.json"
EXTENSOES_IMGS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
EXT_SEM_FOTO = ".SEM_FOTO"
TIMEOUT_CONEXAO = 10.0
TIMEOUT_LEITURA = 30.0
CHUNK_SIZE = 8_192
MAX_RETRIES = 3
THUMBNAIL_SIZE = (140, 140)
GALLERY_COLS = 4

# =============================================================================
# [CAMADA 1 + 2 + 3] SecurityManager — Autenticacao, Criptografia e Auditoria
# =============================================================================


class SecurityManager:
    """
    Gerencia toda a seguranca do aplicativo:

    - Autenticacao: PBKDF2-SHA256 com salt aleatorio (480k iteracoes)
    - Lockout: 60 segundos apos 3 tentativas erradas
    - Criptografia: Fernet (AES-256-CBC + HMAC) para o Webhook URL
    - Auditoria: log append-only com timestamp e nome da maquina

    Estrutura do config.dat (JSON — o webhook_token e o unico dado cifrado):
    {
      "auth_salt":      "<16 bytes hex>",
      "auth_hash":      "<PBKDF2 hash hex>",
      "crypto_salt":    "<16 bytes hex>",
      "webhook_token":  "<Fernet base64 token>",
      "falhas":         0,
      "bloqueado_ate":  null
    }
    """

    CONFIG_FILE = BASE_DIR / "config.dat"
    AUDIT_FILE = BASE_DIR / "auditoria.log"
    MAX_TENTATIVAS = 3
    LOCKOUT_SEGUNDOS = 60
    PBKDF2_ITERS = 480_000  # NIST SP 800-132 recomenda >= 210k para SHA-256

    def __init__(self):
        self.autenticado: bool = False
        self._fernet: Fernet | None = None
        self._config: dict = {}

    # ── Inicializacao ─────────────────────────────────────────────────────────

    def primeiro_uso(self) -> bool:
        """True se ainda nao foi configurada uma senha."""
        return not self.CONFIG_FILE.exists()

    # ── Hashing e Derivacao de Chaves ─────────────────────────────────────────

    def _hash_senha(self, senha: str, salt_hex: str) -> str:
        """PBKDF2-SHA256 com 480k iteracoes. Retorna hex do digest."""
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac(
            "sha256", senha.encode("utf-8"), salt, self.PBKDF2_ITERS
        )
        return dk.hex()

    def _derivar_fernet(self, senha: str, salt_hex: str) -> Fernet:
        """Deriva chave Fernet de 256 bits a partir da senha e salt."""
        salt = bytes.fromhex(salt_hex)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERS,
        )
        chave = base64.urlsafe_b64encode(kdf.derive(senha.encode("utf-8")))
        return Fernet(chave)

    # ── Persistencia do Config ────────────────────────────────────────────────

    def _ler_config(self) -> dict:
        try:
            with open(self.CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _salvar_config(self, config: dict) -> None:
        with open(self.CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    # ── Criacao de Senha (Primeiro Uso) ───────────────────────────────────────

    def criar_senha(self, senha: str, nome: str, departamento: str) -> bool:
        """
        Configura a senha no primeiro uso e salva o perfil.
        Gera dois salts independentes: um para autenticacao, outro para criptografia.
        """
        try:
            auth_salt = os.urandom(16).hex()
            crypto_salt = os.urandom(16).hex()
            auth_hash = self._hash_senha(senha, auth_salt)
            self._fernet = self._derivar_fernet(senha, crypto_salt)
            config = {
                "auth_salt": auth_salt,
                "auth_hash": auth_hash,
                "crypto_salt": crypto_salt,
                "webhook_token": "",
                "falhas": 0,
                "bloqueado_ate": None,
                "nome": nome,
                "departamento": departamento,
            }
            self._salvar_config(config)
            self._config = config
            self.autenticado = True
            self.auditar("SENHA_CRIADA", "Primeiro uso — senha configurada")
            return True
        except Exception:
            return False

    def resetar_app(self) -> None:
        """Apaga o arquivo de configuracao, forçando recadastramento."""
        try:
            if self.CONFIG_FILE.exists():
                self.CONFIG_FILE.unlink()
            self.autenticado = False
            self._config = {}
            self._fernet = None
            self.auditar("APP_RESET", "Configuração local excluida a pedido do usuario")
        except Exception:
            pass

    # ── Lockout ───────────────────────────────────────────────────────────────

    def verificar_lockout(self) -> tuple[bool, int]:
        """Retorna (bloqueado, segundos_restantes)."""
        config = self._ler_config()
        bloqueado_ate = config.get("bloqueado_ate")
        if bloqueado_ate:
            try:
                dt_fim = datetime.fromisoformat(bloqueado_ate)
                restante = int((dt_fim - datetime.now()).total_seconds())
                if restante > 0:
                    return True, restante
                # Lockout expirou: reset
                config["bloqueado_ate"] = None
                config["falhas"] = 0
                self._salvar_config(config)
            except Exception:
                pass
        return False, 0

    # ── Autenticacao ──────────────────────────────────────────────────────────

    def autenticar(self, senha: str) -> tuple[bool, str]:
        """
        Verifica a senha e prepara o Fernet para descriptografar o Webhook.
        Retorna (sucesso, mensagem_para_usuario).
        """
        bloqueado, restante = self.verificar_lockout()
        if bloqueado:
            return False, f"App bloqueado. Aguarde {restante} segundo(s)."

        config = self._ler_config()
        if not config:
            return False, "Arquivo de configuracao corrompido. Contate o administrador."

        hash_calculado = self._hash_senha(senha, config["auth_salt"])
        maquina = os.environ.get("COMPUTERNAME", "desconhecida")

        if hash_calculado == config["auth_hash"]:
            # Senha correta
            config["falhas"] = 0
            config["bloqueado_ate"] = None
            self._salvar_config(config)
            self._config = config
            self._fernet = self._derivar_fernet(senha, config["crypto_salt"])
            self.autenticado = True
            self.auditar("LOGIN_OK", f"Maquina: {maquina}")
            return True, "OK"

        # Senha errada
        falhas = config.get("falhas", 0) + 1
        config["falhas"] = falhas
        self.auditar(
            "LOGIN_FALHA",
            f"Maquina: {maquina} | Tentativa {falhas}/{self.MAX_TENTATIVAS}",
        )

        if falhas >= self.MAX_TENTATIVAS:
            config["bloqueado_ate"] = (
                datetime.now() + timedelta(seconds=self.LOCKOUT_SEGUNDOS)
            ).isoformat()
            config["falhas"] = 0
            self._salvar_config(config)
            self.auditar(
                "LOCKOUT",
                f"Maquina: {maquina} | App bloqueado por {self.LOCKOUT_SEGUNDOS}s",
            )
            return (
                False,
                f"Muitas tentativas. App bloqueado por {self.LOCKOUT_SEGUNDOS} segundos.",
            )

        self._salvar_config(config)
        restantes = self.MAX_TENTATIVAS - falhas
        return False, f"Senha incorreta. {restantes} tentativa(s) restante(s)."

    # ── Webhook URL Criptografado ─────────────────────────────────────────────

    def get_webhook_url(self) -> str:
        """
        Descriptografa e retorna o Webhook URL.
        Nunca retorna o token cifrado — apenas o valor em memória.
        """
        if not self._fernet:
            return ""
        token = self._config.get("webhook_token", "")
        if not token:
            return ""
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, Exception):
            return ""

    def salvar_webhook_url(self, url: str) -> bool:
        """
        Criptografa o Webhook URL com Fernet (AES-256) e persiste no config.dat.
        O URL nunca e salvo em texto puro no disco.
        """
        if not self._fernet or not url:
            return False
        try:
            encrypted = self._fernet.encrypt(url.encode("utf-8")).decode("ascii")
            config = self._ler_config()
            config["webhook_token"] = encrypted
            self._salvar_config(config)
            self._config["webhook_token"] = encrypted
            self.auditar("WEBHOOK_SALVO", "URL do Webhook atualizada e criptografada")
            return True
        except Exception:
            return False

    # ── Auditoria ─────────────────────────────────────────────────────────────

    def auditar(self, acao: str, detalhe: str = "") -> None:
        """
        Registra evento no log de auditoria (append-only) e envia para o PHP remotamente.
        Nunca loga a senha nem o Webhook URL.
        """
        maquina = os.environ.get("COMPUTERNAME", "Desconhecida")
        nome = self._config.get("nome", "Desconhecido")
        departamento = self._config.get("departamento", "Desconhecido")

        # Log Local
        try:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            linha = f"[{ts}] {acao:<20} | {detalhe}\n"
            with open(self.AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(linha)
        except Exception:
            pass

        # Envio Remoto para o cPanel (assíncrono)
        if API_LOGGER_URL:

            def _enviar():
                try:
                    payload = {
                        "nome": nome,
                        "departamento": departamento,
                        "maquina": maquina,
                        "acao": acao,
                        "detalhes": detalhe,
                    }
                    headers = {
                        "X-Audit-Token": API_LOGGER_TOKEN,
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    }
                    requests.post(
                        API_LOGGER_URL, json=payload, headers=headers, timeout=5
                    )
                except Exception:
                    pass

            threading.Thread(target=_enviar, daemon=True).start()


# =============================================================================
# Tela de Criacao de Senha (Primeiro Uso)
# =============================================================================


class JanelaCriarSenha(ctk.CTkToplevel):
    """Exibida apenas no primeiro uso para criar a senha de acesso."""

    def __init__(self, parent, sec: SecurityManager):
        super().__init__(parent)
        self.sec = sec
        self.title("Configuracao Inicial")
        self.geometry("460x580")
        self.resizable(False, False)
        self.configure(fg_color=BG_DARK)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancelar)
        self._build()

    def _build(self):
        ctk.CTkLabel(
            self,
            text="Primeiro Acesso",
            font=ctk.CTkFont("Segoe UI", 20, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(pady=(32, 4))
        ctk.CTkLabel(
            self,
            text="Crie seu perfil e uma senha de acesso.",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY,
        ).pack(pady=(0, 20))

        card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12)
        card.pack(padx=32, fill="x")

        # Perfil
        ctk.CTkLabel(
            card,
            text="Seu Nome Completo:",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=16, pady=(16, 4))
        self.entry_nome = ctk.CTkEntry(
            card,
            height=40,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self.entry_nome.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkLabel(
            card,
            text="Seu Departamento:",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=16, pady=(0, 4))
        self.entry_depto = ctk.CTkEntry(
            card,
            height=40,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self.entry_depto.pack(fill="x", padx=16, pady=(0, 16))

        # Divisor
        ctk.CTkFrame(card, height=1, fg_color=BORDER_COLOR).pack(
            fill="x", padx=16, pady=4
        )

        # Senha
        ctk.CTkLabel(
            card,
            text="Nova senha (minimo 6 caracteres):",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=16, pady=(12, 4))
        self.entry_senha = ctk.CTkEntry(
            card,
            show="•",
            height=40,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont("Segoe UI", 14),
        )
        self.entry_senha.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkLabel(
            card,
            text="Confirmar senha:",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=16)
        self.entry_confirma = ctk.CTkEntry(
            card,
            show="•",
            height=40,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont("Segoe UI", 14),
        )
        self.entry_confirma.pack(fill="x", padx=16, pady=(4, 16))

        # O botão agora está dentro do 'card'
        ctk.CTkButton(
            card,
            text="Salvar Perfil e Continuar",
            font=ctk.CTkFont("Segoe UI", 14, "bold"),
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_ON_ACCENT,
            height=40,
            corner_radius=8,
            command=self._confirmar,
        ).pack(padx=16, pady=(10, 16), fill="x")

        self.lbl_erro = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=ERROR_CLR,
        )
        self.lbl_erro.pack(pady=(10, 0))
        self.entry_senha.bind("<Return>", lambda e: self.entry_confirma.focus())
        self.entry_confirma.bind("<Return>", lambda e: self._confirmar())
        self.entry_nome.focus()

    def _confirmar(self):
        nome = self.entry_nome.get().strip()
        depto = self.entry_depto.get().strip()
        senha = self.entry_senha.get()
        confirma = self.entry_confirma.get()

        if not nome or not depto:
            self.lbl_erro.configure(text="Preencha seu Nome e Departamento.")
            return
        if len(senha) < 6:
            self.lbl_erro.configure(text="A senha deve ter ao menos 6 caracteres.")
            return
        if senha != confirma:
            self.lbl_erro.configure(text="As senhas nao coincidem. Tente novamente.")
            self.entry_confirma.delete(0, "end")
            return

        if self.sec.criar_senha(senha, nome, depto):
            self.destroy()
        else:
            self.lbl_erro.configure(text="Erro ao criar senha. Tente novamente.")

    def _cancelar(self):
        self.sec.autenticado = False
        self.destroy()


# =============================================================================
# Tela de Login
# =============================================================================


class JanelaLogin(ctk.CTkToplevel):
    """Exibida a cada abertura do app para autenticar o usuario."""

    def __init__(self, parent, sec: SecurityManager):
        super().__init__(parent)
        self.sec = sec
        self.reset_solicitado = False
        self.title("Bitrix24 — Acesso")
        self.geometry("420x450")
        self.resizable(False, False)
        self.configure(fg_color=BG_DARK)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancelar)
        self._lockout_ativo = False
        self._build()
        # Verifica lockout preexistente ao abrir
        self.after(100, self._checar_lockout_inicial)

    def _build(self):
        ctk.CTkLabel(
            self,
            text="Bitrix24",
            font=ctk.CTkFont("Segoe UI", 28, "bold"),
            text_color=ACCENT,
        ).pack(pady=(40, 4))
        ctk.CTkLabel(
            self,
            text="Downloader de Fotos  |  Acesso Restrito",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY,
        ).pack()

        card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12)
        card.pack(padx=36, fill="x", pady=24)

        ctk.CTkLabel(
            card,
            text="Senha de acesso:",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=16, pady=(16, 4))
        self.entry_senha = ctk.CTkEntry(
            card,
            show="•",
            height=44,
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont("Segoe UI", 15),
        )
        self.entry_senha.pack(fill="x", padx=16, pady=(0, 16))
        self.entry_senha.bind("<Return>", lambda e: self._entrar())

        self.lbl_erro = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=ERROR_CLR,
        )
        self.lbl_erro.pack()

        self.btn_entrar = ctk.CTkButton(
            self,
            text="Entrar",
            font=ctk.CTkFont("Segoe UI", 14, "bold"),
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_ON_ACCENT,
            height=46,
            corner_radius=8,
            command=self._entrar,
        )
        self.btn_entrar.pack(padx=36, pady=(16, 8), fill="x")

        # Botao Esqueci a senha
        ctk.CTkButton(
            self,
            text="Esqueci minha senha / Resetar App",
            font=ctk.CTkFont("Segoe UI", 11, underline=True),
            fg_color="transparent",
            hover_color=BG_CARD,
            text_color=TEXT_SECONDARY,
            height=30,
            command=self._resetar,
        ).pack(padx=36, pady=(0, 16), fill="x")

        self.entry_senha.focus()

    def _resetar(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Aviso")
        dialog.geometry("380x210")
        dialog.configure(fg_color=BG_DARK)
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text="Resetar o Aplicativo?",
            font=ctk.CTkFont("Segoe UI", 16, "bold"),
            text_color=ERROR_CLR,
        ).pack(pady=(20, 10))
        ctk.CTkLabel(
            dialog,
            text="Isso apagará sua senha, perfil e configurações.\nVocê precisará colar a URL do Webhook\ne criar a conta novamente.",
            text_color=TEXT_PRIMARY,
            justify="center",
        ).pack()

        row = ctk.CTkFrame(dialog, fg_color="transparent")
        row.pack(pady=20)

        def _confirmar():
            self.sec.resetar_app()
            self.reset_solicitado = True
            dialog.destroy()
            self.destroy()

        ctk.CTkButton(
            row,
            text="Cancelar",
            width=100,
            fg_color=BG_CARD,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=dialog.destroy,
        ).pack(side="left", padx=10)
        ctk.CTkButton(
            row,
            text="Apagar Tudo",
            width=120,
            fg_color=ERROR_CLR,
            hover_color="#B91C1C",
            text_color="white",
            command=_confirmar,
        ).pack(side="left", padx=10)

    def _checar_lockout_inicial(self):
        bloqueado, restante = self.sec.verificar_lockout()
        if bloqueado:
            self._iniciar_lockout(restante)

    def _iniciar_lockout(self, segundos: int):
        self._lockout_ativo = True
        self.btn_entrar.configure(state="disabled")
        self.entry_senha.configure(state="disabled")
        self._tick_lockout(segundos)

    def _tick_lockout(self, restante: int):
        if restante <= 0:
            self._lockout_ativo = False
            self.btn_entrar.configure(state="normal")
            self.entry_senha.configure(state="normal")
            self.lbl_erro.configure(text="")
            self.entry_senha.focus()
            return
        self.lbl_erro.configure(
            text=f"Bloqueado. Aguarde {restante}s apos {self.sec.MAX_TENTATIVAS} tentativas erradas."
        )
        try:
            self.after(1000, self._tick_lockout, restante - 1)
        except Exception:
            pass

    def _entrar(self):
        if self._lockout_ativo:
            return
        senha = self.entry_senha.get()
        if not senha:
            return

        self.btn_entrar.configure(state="disabled", text="Verificando...")
        self.update()

        sucesso, msg = self.sec.autenticar(senha)
        if sucesso:
            self.destroy()
            return

        self.entry_senha.delete(0, "end")
        self.lbl_erro.configure(text=msg)
        self.btn_entrar.configure(state="normal", text="Entrar")

        # Verifica se o lockout foi ativado
        bloqueado, restante = self.sec.verificar_lockout()
        if bloqueado:
            self._iniciar_lockout(restante)
        else:
            self.entry_senha.focus()

    def _cancelar(self):
        self.sec.autenticado = False
        self.destroy()


# =============================================================================
# Logica de Download (roda em thread separada — sem alteracoes de seguranca)
# =============================================================================


def _criar_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _limpar_nome(nome: str) -> str:
    n = re.sub(r'[\\/*?:"<>|]', "", nome).strip()
    n = n.replace("/", "").replace("\\", "").replace("..", "")
    return n[:200] if n else "sem_nome"


def _detectar_ext(url: str, ct: str | None = None) -> str:
    p = urlparse(url).path.lower()
    for ext in EXTENSOES_IMGS:
        if p.endswith(ext):
            return ext
    if ct:
        e = mimetypes.guess_extension(ct.split(";")[0].strip())
        if e and e in EXTENSOES_IMGS:
            return e
    return ".jpg"


def _resolver_url(foto_url: str, webhook_url: str) -> str:
    if foto_url.startswith("http"):
        return foto_url
    base = "{scheme}://{netloc}".format(**urlparse(webhook_url)._asdict())
    return urljoin(base, foto_url)


def _carregar_indice() -> dict:
    if ARQUIVO_INDICE.exists():
        try:
            with open(ARQUIVO_INDICE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _salvar_indice(indice: dict) -> None:
    try:
        with open(ARQUIVO_INDICE, "w", encoding="utf-8") as f:
            json.dump(indice, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _registrar(indice, uid, nome, arquivo, url, tem_foto):
    indice[uid] = {
        "nome": nome,
        "arquivo": arquivo,
        "foto_url": url,
        "tem_foto": tem_foto,
        "atualizado_em": datetime.now().isoformat(timespec="seconds"),
    }


def _baixar_imagem(session, url, dest) -> bool:
    try:
        with session.get(
            url, stream=True, timeout=(TIMEOUT_CONEXAO, TIMEOUT_LEITURA)
        ) as r:
            if r.status_code != 200:
                return False
            ct = r.headers.get("Content-Type", "")
            if ct and not ct.startswith("image/"):
                return False
            with open(dest, "wb") as f:
                for chunk in r.iter_content(CHUNK_SIZE):
                    if chunk:
                        f.write(chunk)
        return True
    except Exception:
        return False


def _remover_se_existe(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass


def download_worker(webhook_url: str, queue: Queue, stop_event: threading.Event):
    """Worker de download em thread separada. Envia eventos para a queue."""

    def log(level, msg):
        queue.put(("log", level, msg))

    def progress(cur, tot):
        queue.put(("progress", cur, tot))

    def status(msg):
        queue.put(("status", msg))

    PASTA_DESTINO.mkdir(parents=True, exist_ok=True)
    indice = _carregar_indice()
    session = _criar_session()
    url_api = f"{webhook_url.rstrip('/')}/user.get"

    stats = dict(
        processados=0,
        novos=0,
        atualizados=0,
        sem_mudanca=0,
        novos_com_foto=0,
        sem_foto=0,
        erros=0,
    )
    nomes_sem_foto: list[str] = []

    # Contagem total para a barra de progresso
    total, start = 0, 0
    log("info", "Contando usuarios no portal Bitrix24...")
    while not stop_event.is_set():
        try:
            r = session.get(
                url_api,
                params={"start": start, "ACTIVE": "Y"},
                timeout=(TIMEOUT_CONEXAO, TIMEOUT_LEITURA),
            )
            r.raise_for_status()
            d = r.json()
            total += len(d.get("result", []))
            if "next" in d:
                start = d["next"]
            else:
                break
        except Exception as e:
            log("error", f"Erro ao contar usuarios: {e}")
            break

    log("info", f"{total} usuarios encontrados.")
    progress(0, total)

    start, processados = 0, 0
    while not stop_event.is_set():
        try:
            r = session.get(
                url_api,
                params={"start": start, "ACTIVE": "Y"},
                timeout=(TIMEOUT_CONEXAO, TIMEOUT_LEITURA),
            )
            r.raise_for_status()
        except Exception as e:
            log("error", f"Erro na API: {e}")
            break

        dados = r.json()
        usuarios = dados.get("result", [])
        if not usuarios:
            break

        for u in usuarios:
            if stop_event.is_set():
                break
            if u.get("ACTIVE") is False:
                continue

            processados += 1
            stats["processados"] = processados
            progress(processados, total)

            uid = str(u.get("ID", ""))
            nome = f"{(u.get('NAME') or '').strip()} {(u.get('LAST_NAME') or '').strip()}".strip()
            nome_completo = nome or f"Usuario_ID_{uid}"
            nome_base = f"{_limpar_nome(nome_completo)}_ID{uid}"

            status(f"Processando: {nome_completo}")
            foto_raw = u.get("PERSONAL_PHOTO")

            if not foto_raw:
                ph = PASTA_DESTINO / f"{nome_base}{EXT_SEM_FOTO}"
                entrada = indice.get(uid, {})
                if not (not entrada.get("tem_foto", True) and entrada):
                    ph.touch(exist_ok=True)
                    _registrar(indice, uid, nome_completo, None, None, False)
                    log("warning", f"[SEM FOTO] {nome_completo}")
                else:
                    if not ph.exists():
                        ph.touch(exist_ok=True)
                nomes_sem_foto.append(nome_completo)
                stats["sem_foto"] += 1
                continue

            foto_url = _resolver_url(foto_raw, webhook_url)
            ext = _detectar_ext(foto_url)
            nome_arq = f"{nome_base}{ext}"
            dest_foto = PASTA_DESTINO / nome_arq
            dest_ph = PASTA_DESTINO / f"{nome_base}{EXT_SEM_FOTO}"
            entrada = indice.get(uid, {})
            url_reg = entrada.get("foto_url")
            arq_reg = entrada.get("arquivo")

            if dest_ph.exists():
                _remover_se_existe(dest_ph)
                ok = _baixar_imagem(session, foto_url, dest_foto)
                if ok:
                    _registrar(indice, uid, nome_completo, nome_arq, foto_url, True)
                    log("success", f"[NOVO COM FOTO] {nome_completo}")
                    stats["novos_com_foto"] += 1
                else:
                    log("error", f"[ERRO] Falha ao baixar foto de {nome_completo}")
                    stats["erros"] += 1
                continue

            if url_reg and url_reg == foto_url:
                log("info", f"[OK] {nome_completo}")
                stats["sem_mudanca"] += 1
                continue

            if url_reg and url_reg != foto_url:
                if arq_reg:
                    _remover_se_existe(PASTA_DESTINO / arq_reg)
                _remover_se_existe(dest_foto)
                ok = _baixar_imagem(session, foto_url, dest_foto)
                if ok:
                    _registrar(indice, uid, nome_completo, nome_arq, foto_url, True)
                    log("success", f"[ATUALIZADO] {nome_completo} — foto nova baixada")
                    stats["atualizados"] += 1
                else:
                    log("error", f"[ERRO] Falha ao atualizar foto de {nome_completo}")
                    stats["erros"] += 1
                continue

            if dest_foto.exists():
                _registrar(indice, uid, nome_completo, nome_arq, foto_url, True)
                log("info", f"[SINCRONIZADO] {nome_completo}")
                stats["sem_mudanca"] += 1
                continue

            ok = _baixar_imagem(session, foto_url, dest_foto)
            if ok:
                _registrar(indice, uid, nome_completo, nome_arq, foto_url, True)
                log("success", f"[NOVO] {nome_completo}")
                stats["novos"] += 1
            else:
                log("error", f"[ERRO] Falha ao baixar foto de {nome_completo}")
                stats["erros"] += 1

        _salvar_indice(indice)
        if "next" in dados:
            start = dados["next"]
        else:
            break

    if stop_event.is_set():
        log("warning", "Download cancelado pelo usuario.")

    session.close()
    _salvar_indice(indice)
    queue.put(("done", stats, nomes_sem_foto))


# =============================================================================
# Janela de Visualizacao de Foto
# =============================================================================


class JanelaFoto(ctk.CTkToplevel):
    """Exibe uma foto com navegacao, abertura no visualizador padrao e compartilhamento."""

    def __init__(self, parent, fotos: list[Path], idx: int):
        super().__init__(parent)
        self.fotos = fotos
        self.idx = idx
        self.title("Visualizador")
        self.geometry("760x630")
        self.configure(fg_color=BG_DARK)
        self.grab_set()
        self._build()
        self._carregar(self.idx)

    def _build(self):
        self.img_label = ctk.CTkLabel(self, text="", fg_color=BG_CARD, corner_radius=12)
        self.img_label.pack(fill="both", expand=True, padx=20, pady=(20, 8))

        self.nome_label = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=TEXT_SECONDARY,
        )
        self.nome_label.pack()

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=12)

        ctk.CTkButton(
            row,
            text="< Anterior",
            width=110,
            fg_color=BG_CARD,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._anterior,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            row,
            text="Abrir no Visualizador",
            width=190,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_ON_ACCENT,
            command=self._abrir,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            row,
            text="Compartilhar",
            width=130,
            fg_color=BG_CARD,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._compartilhar,
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            row,
            text="Proximo >",
            width=110,
            fg_color=BG_CARD,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self._proximo,
        ).pack(side="left", padx=4)

        self.bind("<Left>", lambda e: self._anterior())
        self.bind("<Right>", lambda e: self._proximo())
        self.bind("<Escape>", lambda e: self.destroy())

    def _carregar(self, idx: int):
        if not (0 <= idx < len(self.fotos)):
            return
        self.idx = idx
        path = self.fotos[idx]
        self.nome_label.configure(text=path.name)
        try:
            img = Image.open(path)
            img.thumbnail((690, 480), Image.LANCZOS)
            ci = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
            self.img_label.configure(image=ci, text="")
            self.img_label._img = ci
        except Exception:
            self.img_label.configure(
                text="Nao foi possivel carregar a imagem.", image=None
            )

    def _anterior(self):
        self._carregar(self.idx - 1)

    def _proximo(self):
        self._carregar(self.idx + 1)

    def _abrir(self):
        try:
            if sys.platform == "win32":
                os.startfile(str(self.fotos[self.idx]))
            else:
                subprocess.Popen(["xdg-open", str(self.fotos[self.idx])])
        except Exception:
            pass

    def _compartilhar(self):
        try:
            if sys.platform == "win32":
                subprocess.Popen(f'explorer /select,"{self.fotos[self.idx]}"')
            else:
                self.clipboard_clear()
                self.clipboard_append(str(self.fotos[self.idx]))
        except Exception:
            pass


# =============================================================================
# Aplicativo Principal
# =============================================================================


class BitrixApp(ctk.CTk):
    def __init__(self, sec: SecurityManager):
        super().__init__()
        self.sec = sec
        self.title("Bitrix24 — Downloader de Fotos")
        self.geometry("1060x780")
        self.minsize(900, 660)
        self.configure(fg_color=BG_DARK)

        self._queue = Queue()
        self._stop_event = threading.Event()
        self._thread = None
        self._fotos_lista: list[Path] = []

        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        self._build_header()
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=14)
        self._build_actions(content)
        self._build_tabs(content)

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=0, height=68)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        esq = ctk.CTkFrame(hdr, fg_color="transparent")
        esq.pack(side="left", padx=20, pady=10)
        ctk.CTkLabel(
            esq,
            text="Bitrix24",
            font=ctk.CTkFont("Segoe UI", 22, "bold"),
            text_color=ACCENT,
        ).pack(side="left")
        ctk.CTkLabel(
            esq,
            text="  Downloader de Fotos",
            font=ctk.CTkFont("Segoe UI", 18),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        ctk.CTkLabel(
            hdr,
            text="v2.1  |  by INFINITYTEK",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=TEXT_SECONDARY,
        ).pack(side="right", padx=20)

    def _build_actions(self, parent):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12)
        card.pack(fill="x", pady=(0, 10))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(12, 8))

        self.btn_start = ctk.CTkButton(
            btn_row,
            text="  Iniciar Download",
            font=ctk.CTkFont("Segoe UI", 14, "bold"),
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_ON_ACCENT,
            height=44,
            width=200,
            corner_radius=8,
            command=self._iniciar,
        )
        self.btn_start.pack(side="left", padx=(0, 8))

        self.btn_stop = ctk.CTkButton(
            btn_row,
            text="  Cancelar",
            font=ctk.CTkFont("Segoe UI", 13),
            fg_color=BORDER_COLOR,
            hover_color="#4B5563",
            text_color=TEXT_SECONDARY,
            height=44,
            width=130,
            corner_radius=8,
            state="disabled",
            command=self._cancelar,
        )
        self.btn_stop.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row,
            text="  Abrir Pasta",
            font=ctk.CTkFont("Segoe UI", 13),
            fg_color=BORDER_COLOR,
            hover_color="#4B5563",
            text_color=TEXT_SECONDARY,
            height=44,
            width=140,
            corner_radius=8,
            command=self._abrir_pasta,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row,
            text="  Log de Auditoria",
            font=ctk.CTkFont("Segoe UI", 13),
            fg_color=BORDER_COLOR,
            hover_color="#4B5563",
            text_color=TEXT_SECONDARY,
            height=44,
            width=165,
            corner_radius=8,
            command=self._abrir_auditoria,
        ).pack(side="left")

        prog = ctk.CTkFrame(card, fg_color="transparent")
        prog.pack(fill="x", padx=16, pady=(0, 12))

        self.progress_bar = ctk.CTkProgressBar(
            prog,
            fg_color="#0F172A",
            progress_color=ACCENT,
            height=8,
            corner_radius=4,
        )
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", pady=(0, 6))

        status_row = ctk.CTkFrame(prog, fg_color="transparent")
        status_row.pack(fill="x")
        self.lbl_status = ctk.CTkLabel(
            status_row,
            text="Pronto para iniciar.",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        self.lbl_status.pack(side="left", fill="x", expand=True)
        self.lbl_pct = ctk.CTkLabel(
            status_row,
            text="0%",
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            text_color=ACCENT,
            width=40,
        )
        self.lbl_pct.pack(side="right")

    def _build_tabs(self, parent):
        self.tabview = ctk.CTkTabview(
            parent,
            fg_color=BG_CARD,
            segmented_button_fg_color=BG_CARD,
            segmented_button_selected_color=ACCENT,
            segmented_button_selected_hover_color=ACCENT_HOVER,
            segmented_button_unselected_color=BG_CARD,
            segmented_button_unselected_hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            corner_radius=12,
        )
        self.tabview.pack(fill="both", expand=True)
        self.tabview.add("  Log  ")
        self.tabview.add("  Galeria de Fotos  ")

        self.log_box = ctk.CTkTextbox(
            self.tabview.tab("  Log  "),
            font=ctk.CTkFont("Consolas", 11),
            fg_color="#080F1A",
            text_color=TEXT_PRIMARY,
            corner_radius=8,
            wrap="none",
            state="disabled",
        )
        self.log_box.pack(fill="both", expand=True, padx=8, pady=8)

        self.gallery_container = ctk.CTkFrame(
            self.tabview.tab("  Galeria de Fotos  "),
            fg_color="transparent",
        )
        self.gallery_container.pack(fill="both", expand=True)
        self.gallery_placeholder = ctk.CTkLabel(
            self.gallery_container,
            text="Execute o download para ver as fotos aqui.",
            font=ctk.CTkFont("Segoe UI", 14),
            text_color=TEXT_SECONDARY,
        )
        self.gallery_placeholder.pack(expand=True)
        self.gallery_scroll = None

    # ── Acoes ────────────────────────────────────────────────────────────────

    def _iniciar(self):
        url = API_WEBHOOK_URL.strip()
        if not url:
            self._log("error", "Constante API_WEBHOOK_URL não configurada no código.")
            return
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http"):
            self._log("error", "URL invalida — deve comecar com https://")
            return

        self._clear_log()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal", text_color=ERROR_CLR)
        self._stop_event.clear()
        self.progress_bar.set(0)
        self.lbl_pct.configure(text="0%")
        self._clear_gallery()

        self.sec.auditar("DOWNLOAD_INICIO", f"Portal: {parsed.netloc}")

        self._thread = threading.Thread(
            target=download_worker,
            args=(url, self._queue, self._stop_event),
            daemon=True,
        )
        self._thread.start()
        self._log("info", f"Iniciando download em {parsed.netloc}")
        self.tabview.set("  Log  ")

    def _cancelar(self):
        self._stop_event.set()
        self.btn_stop.configure(state="disabled")
        self.lbl_status.configure(text="Cancelando, aguarde...")
        self.sec.auditar("DOWNLOAD_CANCELADO")

    def _abrir_pasta(self):
        PASTA_DESTINO.mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            subprocess.Popen(f'explorer "{PASTA_DESTINO}"')
        else:
            subprocess.Popen(["xdg-open", str(PASTA_DESTINO)])

    def _abrir_auditoria(self):
        """Abre o arquivo de log de auditoria no editor de texto padrao."""
        audit_path = SecurityManager.AUDIT_FILE
        if not audit_path.exists():
            self._log("warning", "Nenhum registro de auditoria ainda.")
            return
        try:
            if sys.platform == "win32":
                os.startfile(str(audit_path))
        except Exception as e:
            self._log("error", f"Nao foi possivel abrir o log: {e}")

    # ── Log ──────────────────────────────────────────────────────────────────

    def _log(self, level: str, msg: str):
        prefixes = {
            "info": "  [INFO]     ",
            "success": "  [OK]       ",
            "warning": "  [AVISO]    ",
            "error": "  [ERRO]     ",
        }
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{prefixes.get(level, '  [INFO]     ')}{msg}\n")
        self.log_box.configure(state="disabled")
        self.log_box.see("end")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    # ── Queue (thread → UI) ──────────────────────────────────────────────────

    def _poll_queue(self):
        try:
            while True:
                event = self._queue.get_nowait()
                etype = event[0]
                if etype == "log":
                    self._log(event[1], event[2])
                elif etype == "progress":
                    _, cur, tot = event
                    if tot > 0:
                        pct = cur / tot
                        self.progress_bar.set(pct)
                        self.lbl_pct.configure(text=f"{int(pct * 100)}%")
                elif etype == "status":
                    self.lbl_status.configure(text=event[1])
                elif etype == "done":
                    self._on_done(event[1], event[2])
        except Empty:
            pass
        except Exception:
            pass
        self.after(80, self._poll_queue)

    # ── Conclusao ─────────────────────────────────────────────────────────────

    def _on_done(self, stats: dict, nomes_sem_foto: list[str]):
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled", text_color=TEXT_SECONDARY)
        self.progress_bar.set(1)
        self.lbl_pct.configure(text="100%")
        self.lbl_status.configure(text="Download concluido!")

        self.sec.auditar(
            "DOWNLOAD_FIM",
            f"Novos: {stats['novos']} | Atualizados: {stats['atualizados']} "
            f"| Sem foto: {stats['sem_foto']} | Erros: {stats['erros']}",
        )

        self._log("info", "")
        self._log("info", "=" * 52)
        self._log("info", "  RESUMO DA EXECUCAO")
        self._log("info", "=" * 52)
        self._log("info", f"  Total processados   : {stats['processados']}")
        self._log("success", f"  Fotos novas         : {stats['novos']}")
        self._log("success", f"  Fotos atualizadas   : {stats['atualizados']}")
        self._log("info", f"  Sem alteracao       : {stats['sem_mudanca']}")
        self._log("success", f"  Novos com foto      : {stats['novos_com_foto']}")
        self._log("warning", f"  Sem foto            : {stats['sem_foto']}")
        if stats["erros"]:
            self._log("error", f"  Erros               : {stats['erros']}")

        if nomes_sem_foto:
            self._log("warning", f"\n  Usuarios SEM foto ({len(nomes_sem_foto)}):")
            for n in nomes_sem_foto:
                self._log("warning", f"    - {n}")

        self._build_gallery()
        self.tabview.set("  Galeria de Fotos  ")

    # ── Galeria ──────────────────────────────────────────────────────────────

    def _clear_gallery(self):
        if self.gallery_scroll:
            self.gallery_scroll.destroy()
            self.gallery_scroll = None
        self.gallery_placeholder.configure(text="Aguardando conclusao do download...")
        self.gallery_placeholder.pack(expand=True)

    def _build_gallery(self):
        fotos = sorted(
            [p for p in PASTA_DESTINO.iterdir() if p.suffix.lower() in EXTENSOES_IMGS]
        )
        self._fotos_lista = fotos
        if self.gallery_scroll:
            self.gallery_scroll.destroy()
        self.gallery_placeholder.pack_forget()

        tab = self.tabview.tab("  Galeria de Fotos  ")
        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", padx=8, pady=(8, 4))
        ctk.CTkLabel(
            top,
            text=f"{len(fotos)} foto(s) disponivel(is)",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")
        ctk.CTkButton(
            top,
            text="Abrir Pasta",
            font=ctk.CTkFont("Segoe UI", 12),
            fg_color=BORDER_COLOR,
            hover_color="#475569",
            text_color=TEXT_PRIMARY,
            height=32,
            width=120,
            command=self._abrir_pasta,
        ).pack(side="right")

        self.gallery_scroll = ctk.CTkScrollableFrame(
            tab,
            fg_color="#080F1A",
            corner_radius=8,
        )
        self.gallery_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        for c in range(GALLERY_COLS):
            self.gallery_scroll.grid_columnconfigure(c, weight=1)

        self.after(50, self._carregar_galeria_lote, fotos, 0)

    def _carregar_galeria_lote(self, fotos: list[Path], inicio: int):
        LOTE = GALLERY_COLS * 2
        fim = min(inicio + LOTE, len(fotos))
        for idx in range(inicio, fim):
            self._add_card(fotos[idx], idx, idx // GALLERY_COLS, idx % GALLERY_COLS)
        if fim < len(fotos):
            self.after(30, self._carregar_galeria_lote, fotos, fim)

    def _add_card(self, path: Path, foto_idx: int, row: int, col: int):
        card = ctk.CTkFrame(self.gallery_scroll, fg_color=BG_CARD, corner_radius=10)
        card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

        try:
            from PIL import ImageOps
            img = Image.open(path)
            img = ImageOps.fit(img, THUMBNAIL_SIZE, Image.LANCZOS)
            ci = ctk.CTkImage(light_image=img, dark_image=img, size=THUMBNAIL_SIZE)
            lbl = ctk.CTkLabel(
                card, image=ci, text="", cursor="hand2", fg_color="transparent"
            )
            lbl._img = ci
            lbl.pack(padx=8, pady=(10, 4))
            lbl.bind("<Button-1>", lambda e, i=foto_idx: self._abrir_galeria(i))
        except Exception:
            ctk.CTkLabel(
                card,
                text="Imagem\nindisponivel",
                font=ctk.CTkFont("Segoe UI", 10),
                text_color=TEXT_SECONDARY,
                width=140,
                height=140,
            ).pack(padx=8, pady=(10, 4))

        nome = path.stem[:22] + "..." if len(path.stem) > 24 else path.stem
        ctk.CTkLabel(
            card,
            text=nome,
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=TEXT_SECONDARY,
            wraplength=150,
        ).pack(padx=6)

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(pady=(4, 10))
        ctk.CTkButton(
            btn_row,
            text="Ver",
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color="white",
            width=60,
            height=30,
            corner_radius=6,
            command=lambda i=foto_idx: self._abrir_galeria(i),
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            btn_row,
            text="Compartilhar",
            font=ctk.CTkFont("Segoe UI", 11),
            fg_color=BORDER_COLOR,
            hover_color="#475569",
            text_color=TEXT_PRIMARY,
            width=108,
            height=30,
            corner_radius=6,
            command=lambda p=path: self._compartilhar(p),
        ).pack(side="left")

    def _abrir_galeria(self, idx: int):
        if self._fotos_lista:
            JanelaFoto(self, self._fotos_lista, idx)

    def _compartilhar(self, path: Path):
        try:
            if sys.platform == "win32":
                subprocess.Popen(f'explorer /select,"{path}"')
                self._log("info", f"Arquivo selecionado: {path.name}")
            else:
                self.clipboard_clear()
                self.clipboard_append(str(path))
                self._log("success", f"Caminho copiado: {path.name}")
        except Exception as e:
            self._log("error", f"Erro ao compartilhar: {e}")


# Constante global necessaria para o label de aviso de escopo
WARNING_CLR = "#F59E0B"


# =============================================================================
# Ponto de Entrada — Fluxo de Autenticacao
# =============================================================================


def main():
    import tkinter as tk
    from tkinter import messagebox

    if not BASE_DIR.exists():
        root = tk.Tk()
        root.withdraw()
        resposta = messagebox.askyesno(
            "Permissao Necessaria",
            f"O aplicativo precisa criar a pasta {BASE_DIR} no disco local para salvar as configuracoes de acesso e as fotos.\n\nDeseja permitir?",
        )
        if resposta:
            try:
                BASE_DIR.mkdir(parents=True, exist_ok=True)
                PASTA_DESTINO.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                messagebox.showerror(
                    "Erro de Permissao",
                    f"Acesso negado ao tentar criar {BASE_DIR}.\n\nPor favor, execute o aplicativo como Administrador clicando com o botao direito do mouse.",
                )
                sys.exit(1)
            except Exception as e:
                messagebox.showerror("Erro", f"Erro inesperado: {e}")
                sys.exit(1)
        else:
            sys.exit(0)
        root.destroy()

def main():
    sec = SecurityManager()
    app = BitrixApp(sec)
    app.withdraw()  # Oculta antes do mainloop iniciar

    def _verificar_login():
        if sec.primeiro_uso():
            dialogo = JanelaCriarSenha(app, sec)
        else:
            dialogo = JanelaLogin(app, sec)

        app.wait_window(dialogo)

        if sec.autenticado:
            app.deiconify()
            app.state("normal")
            app.attributes("-topmost", True)
            app.after(100, lambda: app.attributes("-topmost", False))
            app.focus_force()
        else:
            reset = getattr(dialogo, "reset_solicitado", False)
            app.destroy()
            if reset:
                main()
            else:
                sys.exit(0)

    app.after(10, _verificar_login)
    app.mainloop()


if __name__ == "__main__":
    main()
