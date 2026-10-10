@echo off
REM ===================================================================
REM  MSCAD regeneration pipeline -- full run
REM  Edit PY below if your Python lives somewhere else.
REM  All paths and semantic switches live in mscad_config.py
REM ===================================================================
setlocal

set PY=C:\Users\banot\AppData\Local\Programs\Python\Python313\python.exe
if not exist "%PY%" (
    echo ERROR: Python not found at %PY%
    echo Edit run_all.bat and set PY to your python.exe
    exit /b 2
)

cd /d "%~dp0"

echo.
echo ############ STAGE 00  inspect the inputs ############
"%PY%" 00_inspect_inputs.py
if errorlevel 1 goto :failed

echo.
echo ############ STAGE 01  PCAP -^> CSV (all six captures) ############
"%PY%" 01_pcap_to_csv.py
if errorlevel 1 goto :failed

echo.
echo ############ STAGE 02  verify the extraction ############
"%PY%" 02_verify.py
if errorlevel 1 goto :failed

echo.
echo ############ STAGE 03  compare with the Kaggle MSCAD.csv ############
"%PY%" 03_compare_with_kaggle.py
if errorlevel 1 goto :failed

echo.
echo ############ STAGE 04  consolidated CSVs ############
"%PY%" 04_consolidate.py
if errorlevel 1 goto :failed

echo.
echo ############ STAGE 05  report ############
"%PY%" 05_report.py
if errorlevel 1 goto :failed

echo.
echo ===================================================================
echo  DONE.  See MSCAD_regeneration_report.md in the output folder.
echo ===================================================================
exit /b 0

:failed
echo.
echo ===================================================================
echo  A STAGE FAILED -- scroll up for the exact error. Nothing was
echo  skipped silently; fix the error and re-run that stage alone.
echo ===================================================================
exit /b 1
