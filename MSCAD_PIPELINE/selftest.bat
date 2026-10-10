@echo off
REM Self-test on synthetic captures -- no MSCAD data needed.
REM Proves the pipeline runs end to end on this machine before you point
REM it at the real PCAPs. Writes only into %TEMP%\mscad_selftest.
setlocal
set PY=C:\Users\banot\AppData\Local\Programs\Python\Python313\python.exe
set T=%TEMP%\mscad_selftest
cd /d "%~dp0"

echo building the synthetic fixture in %T% ...
"%PY%" make_test_fixture.py "%T%"
if errorlevel 1 goto :failed

set OPTS=--pcap-dir "%T%\pcaps\pcapngtopcap" --csv-dir "%T%\csv_original" --out-dir "%T%\out"
"%PY%" 00_inspect_inputs.py %OPTS%
if errorlevel 1 goto :failed
"%PY%" 01_pcap_to_csv.py %OPTS%
if errorlevel 1 goto :failed
"%PY%" 02_verify.py %OPTS%
if errorlevel 1 goto :failed
"%PY%" 03_compare_with_kaggle.py %OPTS%
if errorlevel 1 goto :failed
"%PY%" 04_consolidate.py %OPTS%
if errorlevel 1 goto :failed
"%PY%" 05_report.py %OPTS%
if errorlevel 1 goto :failed
echo.
echo SELF-TEST COMPLETE. Results under %T%\out
echo Look for "NO PROBLEMS FOUND" in the stage 02 output above.
exit /b 0
:failed
echo SELF-TEST FAILED -- see the error above.
exit /b 1
