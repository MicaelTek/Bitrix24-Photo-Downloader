# Bitrix24 Foto Downloader (Edição Segura v2.0)

Este aplicativo é uma solução segura com interface gráfica para baixar fotos de perfil de usuários diretamente de um portal Bitrix24 utilizando Webhooks locais.

## Funcionalidades e Segurança

- **Autenticação Local**: Acesso protegido por senha (hashing PBKDF2-SHA256).
- **Proteção contra Força Bruta**: Bloqueio de 60 segundos após 3 tentativas de login incorretas.
- **Criptografia Ponto a Ponto**: A URL do Webhook do Bitrix24 é salva localmente com criptografia AES-256 (Fernet), amarrada à senha do usuário.
- **Auditoria Remota (cPanel)**: Todos os acessos, downloads e tentativas de login falhas são registrados silenciosamente em um servidor PHP via SQLite, capturando o perfil do usuário (Nome, Departamento) e IP.
- **Interface Gráfica Amigável**: Construída com `customtkinter`, exibindo barra de progresso, botão para interrupção de processos e galeria em tempo real.

## Como Compilar (Gerar o `.exe`)

1. Instale o Python (versão 3.10 ou superior).
2. Instale as dependências executando:
   ```bash
   pip install -r requirements_gui.txt
   ```
3. (Opcional) Configure as variáveis `API_LOGGER_URL` e `API_LOGGER_TOKEN` dentro de `app_gui.py` se for usar o monitoramento remoto.
4. Execute o script de compilação do PyInstaller:
   ```bash
   .\build_exe.bat
   ```
5. O aplicativo pronto para distribuição estará na pasta `dist/Bitrix24 Fotos.exe`.

## Como Distribuir para a Equipe

1. Distribua apenas o arquivo `dist/Bitrix24 Fotos.exe`.
2. **NUNCA** distribua o arquivo `config.dat` (se existir na sua máquina). Cada usuário deve abrir o aplicativo pela primeira vez, criar sua própria senha e configurar a URL do Webhook.

## Auditoria PHP (Opcional)

Se você desejar registrar os acessos de forma remota:
1. Suba o arquivo `logger.php` em seu servidor (ex: cPanel).
2. Configure a constante de segurança `SECRET_TOKEN` no PHP e copie para a variável `API_LOGGER_TOKEN` no Python.
3. O painel SQLite será gerado automaticamente.

## Arquivos do Projeto

- `app_gui.py`: Código-fonte principal do aplicativo.
- `logger.php`: Endpoint para auditoria no servidor web.
- `diagnostico.py`: Ferramenta para testar conectividade e segurança.
- `build_exe.bat`: Script de build (PyInstaller).
