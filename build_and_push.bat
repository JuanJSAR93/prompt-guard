@echo off
setlocal

echo =======================================================
echo Compilando y Publicando Prompt Guard 2 en GHCR
echo =======================================================

set IMAGE_NAME=ghcr.io/juanjsar93/prompt-guard:latest
set GITHUB_USER=JuanJSAR93

if "%GITHUB_TOKEN%"=="" (
    echo [!] Ingrese su token de GitHub para autenticar:
    set /p GITHUB_TOKEN="GitHub Token: "
)

echo [1/3] Autenticando en GitHub Container Registry...
echo %GITHUB_TOKEN% | docker login ghcr.io -u %GITHUB_USER% --password-stdin
if %ERRORLEVEL% neq 0 (
    echo [!] Error al autenticar en GHCR.
    exit /b %ERRORLEVEL%
)

echo.
echo [2/3] Compilando imagen Docker optimizada para CPU...
docker build --platform linux/amd64 -t %IMAGE_NAME% .
if %ERRORLEVEL% neq 0 (
    echo [!] Error durante la compilacion de Docker.
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Subiendo imagen a GHCR (%IMAGE_NAME%)...
docker push %IMAGE_NAME%
if %ERRORLEVEL% neq 0 (
    echo [!] Error al subir la imagen a GHCR.
    exit /b %ERRORLEVEL%
)

echo.
echo =======================================================
echo [OK] Imagen subida exitosamente: %IMAGE_NAME%
echo Ya puedes desplegarla en Coolify usando tu docker-compose.yml
echo =======================================================

endlocal
