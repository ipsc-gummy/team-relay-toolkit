@echo off
setlocal
set "sg_python=%SG_RELAY_PYTHON%"
if defined sg_python goto run
if not exist "%~dp0python-path.txt" goto missing
set /p "sg_python=" < "%~dp0python-path.txt"
:run
if not defined sg_python goto missing
if not exist "%sg_python%" goto missing
"%sg_python%" -X utf8 -B "%~dp0program\install.py" %*
exit /b %errorlevel%
:missing
echo Ask your local Agent to record the verified native Windows Python 3.11+ full path in python-path.txt next to this entry. Do not use MSYS2/Cygwin Python.
exit /b 2
