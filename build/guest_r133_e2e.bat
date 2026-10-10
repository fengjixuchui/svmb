@echo off
rem r133 suite (guest side): mem_crypt dual-frame split view.
rem Full cycle -> hold -> unload-restore leg. ASCII only (guest GBK law).
cd /d "%~dp0"
if exist crypt_hold.txt del crypt_hold.txt
taskkill /f /im mcrypt_target.exe >nul 2>&1
echo === crypte2e full cycle (enc: readvm=cipher, target=plaintext) ===
svmbctl.exe crypte2e
echo CRYPTE2E_EXIT=%ERRORLEVEL%
echo === kernel log drain (trap/forensics) ===
svmbctl.exe log
echo === crypte2e hold (leave encrypted for the unload-restore leg) ===
svmbctl.exe crypte2e hold
echo CRYPTE2E_HOLD_EXIT=%ERRORLEVEL%
echo === sc stop svmb (driver unload - plaintext restore must fire) ===
sc stop svmb
echo SCSTOP_EXIT=%ERRORLEVEL%
ping -n 4 127.0.0.1 >nul
echo === sc start svmb (fresh instance; AutoStart re-enters) ===
sc start svmb
echo SCSTART_EXIT=%ERRORLEVEL%
ping -n 4 127.0.0.1 >nul
if exist crypt_hold.txt goto :chk
echo NO-HOLD-FILE
goto :end
:chk
rem the held child survived the whole sc stop/start cycle. MemCryptDeinit
rem (DevUnload) restored the plaintext; post-restore the child reads the
rem original frame through identity - every self-check line in its output
rem file must say plaintext-ok (a DAMAGED line = restore miss). The file
rem also covers the sealed phase (pre-unload): those lines must be ok too
rem (the target reads its private frame through ProcView).
findstr /c:"PLAINTEXT-DAMAGED" mcrypt_hold_out.txt
echo DAMAGED_FINDSTR_EXIT=%ERRORLEVEL% (1 = no damage lines = PASS)
echo === last self-check lines ===
for /f "usebackq delims=" %%l in (`powershell -nologo -command "Get-Content mcrypt_hold_out.txt -Tail 3"`) do echo %%l
taskkill /f /im mcrypt_target.exe >nul 2>&1
del crypt_hold.txt
:end
echo === r133 suite done ===
