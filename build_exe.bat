@echo off
echo ============================================================
echo  Bitrix24 Fotos - Gerando executavel .exe (Edicao Segura)
echo ============================================================
echo.

python -m PyInstaller --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [INSTALANDO] Dependencias necessarias...
    pip install -r requirements_gui.txt pyinstaller
)

echo.
echo [1/3] Executando Testes de Diagnostico e Validando Segredos (.env)...
echo.
python diagnostico.py
if %errorlevel% neq 0 (
    echo.
    echo [ERRO FATAL] O teste de conexao ou as configuracoes do .env falharam!
    echo Corrija os problemas apontados acima antes de compilar o executavel.
    pause
    exit /b 1
)
echo.

if exist "dist\Bitrix24 Fotos.exe" del /f /q "dist\Bitrix24 Fotos.exe"
if exist "build" rmdir /s /q "build"

echo [2/3] Gerando executavel (pode levar 2-3 minutos)...
echo.

python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "Bitrix24 Fotos" ^
    --collect-all customtkinter ^
    --collect-all PIL ^
    --collect-all cryptography ^
    --hidden-import requests ^
    --hidden-import dotenv ^
    --hidden-import urllib3 ^
    --hidden-import cryptography.hazmat.primitives.kdf.pbkdf2 ^
    --hidden-import cryptography.hazmat.primitives.hashes ^
    --hidden-import cryptography.fernet ^
    app_gui.py

if %errorlevel% neq 0 (
    echo.
    echo [ERRO] Falha ao gerar o executavel. Veja os erros acima.
    pause
    exit /b 1
)

echo.
echo [3/3] Limpando arquivos temporarios...
if exist "build" rmdir /s /q "build"
if exist "Bitrix24 Fotos.spec" del /f /q "Bitrix24 Fotos.spec"

echo.
echo ============================================================
echo  SUCESSO! Executavel gerado em: dist\Bitrix24 Fotos.exe
echo.
echo  Para distribuir ao time de marketing, copie:
echo    dist\Bitrix24 Fotos.exe
echo.
echo  O config.dat e auditoria.log serao criados automaticamente
echo  na mesma pasta onde o .exe for executado.
echo.
echo  IMPORTANTE: NAO distribua o config.dat — cada instancia
echo  deve criar sua propria senha no primeiro uso.
echo ============================================================
echo.
pause
