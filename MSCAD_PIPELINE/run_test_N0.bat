@echo off
REM Quick test: inspect the inputs, then convert N-0 only.
setlocal
set PY=C:\Users\banot\AppData\Local\Programs\Python\Python313\python.exe
cd /d "%~dp0"
"%PY%" 00_inspect_inputs.py
echo.
echo ############ N-0 only ############
"%PY%" 01_pcap_to_csv.py N-0
