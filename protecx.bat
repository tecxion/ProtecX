@echo off
rem Lanzador de ProtecX para Windows.
rem Crea .venv la primera vez, instala solo lo que falte y ejecuta el programa.
rem   protecx.bat                  -> menu con logo y opciones (doble clic)
rem   protecx.bat update           -> cualquier subcomando de protecx
rem Pide permisos de administrador solo (UAC) con el menu o con "scan".
setlocal EnableExtensions
cd /d "%~dp0"
set "PY=.venv\Scripts\python.exe"

rem 0) Privilegios: para ver todos los procesos y conexiones hace falta ser administrador. Con el menu o con
rem    "scan" se reabre solo con permisos elevados (ventana UAC). PROTECX_NO_ELEVATE=1 lo evita.
rem    (Sin bloques con parentesis: "Program Files (x86)" romperia el script.)
if defined PROTECX_NO_ELEVATE goto elevated_ok
fltmc >nul 2>&1 && goto elevated_ok
if not "%~1"=="" if /i not "%~1"=="scan" goto elevated_ok
set "SELF=%~f0"
set "SELF=%SELF:'=''%"
echo [ProtecX] Pidiendo permisos de administrador (ventana UAC)...
if "%~1"=="" goto elev_noargs
powershell -NoProfile -Command "Start-Process -FilePath '%SELF%' -ArgumentList '%*' -Verb RunAs" >nul 2>&1
goto elev_check
:elev_noargs
powershell -NoProfile -Command "Start-Process -FilePath '%SELF%' -Verb RunAs" >nul 2>&1
:elev_check
if errorlevel 1 goto elev_denied
exit /b 0
:elev_denied
echo [ProtecX] No se concedieron permisos de administrador: se continua con permisos limitados.
:elevated_ok

rem 1) Entorno virtual (solo si no existe)
if exist "%PY%" goto have_venv
set "BASEPY="
py -3 -c "import sys; sys.exit(sys.version_info < (3, 9))" >nul 2>&1 && set "BASEPY=py -3"
if not defined BASEPY python -c "import sys; sys.exit(sys.version_info < (3, 9))" >nul 2>&1 && set "BASEPY=python"
if not defined BASEPY goto no_python
echo [ProtecX] Creando entorno virtual en .venv ...
%BASEPY% -m venv .venv || goto fail
:have_venv

rem 2) Dependencias: solo se instalan si no se pueden importar
"%PY%" -c "import psutil" >nul 2>&1 && goto check_yara
echo [ProtecX] Instalando dependencias (psutil) ...
"%PY%" -m pip install --quiet --disable-pip-version-check psutil || goto fail

:check_yara
rem yara-python es opcional: si no hay version para tu Python se anota y no se reintenta
"%PY%" -c "import yara" >nul 2>&1 && goto run
if exist ".venv\yara-no-disponible" goto run
echo [ProtecX] Instalando yara-python (opcional) ...
"%PY%" -m pip install --quiet --disable-pip-version-check yara-python >nul 2>&1 && goto run
echo [ProtecX] Aviso: yara-python no se pudo instalar; se usara sin reglas YARA.
type nul > ".venv\yara-no-disponible"

:run
rem 3) Ejecutar. Sin argumentos: menu con logo (analisis completo, red, archivos...).
if "%~1"=="" goto run_menu
"%PY%" -m protecx %*
goto ran
:run_menu
"%PY%" -m protecx menu
:ran
set "CODE=%ERRORLEVEL%"
goto done

:no_python
echo [ProtecX] Necesito Python 3.9 o superior: https://www.python.org/downloads/ (marca "Add python.exe to PATH").
:fail
set "CODE=1"

:done
rem Si se abrio con doble clic y algo fallo, no cerrar la ventana de golpe
if not "%CODE%"=="0" echo %cmdcmdline% | find /i "/c" >nul && pause
exit /b %CODE%
