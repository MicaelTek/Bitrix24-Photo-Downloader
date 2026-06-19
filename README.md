# Bitrix24 Foto Downloader (by INFINITYTEK)

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

## Como Gerar a URL do Webhook (API Bitrix24)

Para que o aplicativo consiga puxar os dados, a equipe precisará de uma chave de API (Webhook Local) gerada no portal do Bitrix24:

1. Acesse o seu portal do Bitrix24 (ex: `https://sua-empresa.bitrix24.com.br`).
2. No menu lateral, vá em **Aplicativos** (ou Market) > **Desenvolvimento de Aplicativos** (Developer resources).
3. Escolha a opção **Outro** e clique em **Webhook de Entrada** (Inbound webhook).
4. Em **Atribuição de Permissões**, selecione as permissões necessárias:
   - **Usuários (user)**
5. Salve. O sistema vai gerar uma URL única.

## Configurando Segredos (.env) e Compilando

Para não expor dados críticos no código-fonte ou no repositório:
1. Copie o arquivo `.env.example` e renomeie a cópia para `.env` (este arquivo está protegido pelo gitignore).
2. Cole a URL do webhook recém-criada na variável `API_WEBHOOK_URL` dentro do `.env`.
3. (Opcional) Configure as variáveis `API_LOGGER_URL` e `API_LOGGER_TOKEN` se for usar auditoria em PHP.
4. Execute o script de compilação:
   ```bash
   .\build_exe.bat
   ```
5. O aplicativo embutirá essas chaves na memória da compilação de forma segura (utilize o hook do PyInstaller para arquivos invisíveis se necessário). O binário pronto ficará na pasta `dist/`.

## Painel Web de Auditoria (cPanel)

O sistema de auditoria `logger.php` possui agora um Painel de Administração Gráfico embutido (2 em 1) para visualização dos registros enviados pelos usuários.

1. Envie o arquivo `logger.php` para o seu cPanel em uma pasta pública.
2. Acesse a URL dele diretamente pelo navegador: `https://sua-empresa.com.br/pasta/logger.php`
3. Entre com a senha de acesso para visualizar o dashboard com IPs, Máquinas e Histórico.

⚠️ **IMPORTANTE:** A senha padrão de fábrica é **`admin`**. Para sua segurança, é obrigatório abrir o código fonte do arquivo `logger.php` e alterar a constante `VIEWER_PASSWORD` para uma senha forte logo no seu primeiro acesso!



## Arquivos do Projeto

- `app_gui.py`: Código-fonte principal do aplicativo.
- `logger.php`: Endpoint para auditoria no servidor web.
- `diagnostico.py`: Ferramenta para testar conectividade e segurança.
- `build_exe.bat`: Script de build (PyInstaller).
