@echo off
if exist "%~dp0vmenv.bat" call "%~dp0vmenv.bat"
rem r133 hold-leg forensics: what does the guest test dir look like
"%VMRUN%" -T ws -gu %VM_USER% -gp %VM_PASS% runProgramInGuest "%VM_VMX%" "C:\Windows\System32\cmd.exe" "/c (dir %GUEST_TEST_DIR%\mcrypt* & echo === & type %GUEST_TEST_DIR%\mcrypt_hold_out.txt & echo === & tasklist | findstr mcrypt) > %GUEST_TEST_DIR%\r133_probe.txt 2>&1 < NUL"
"%VMRUN%" -T ws -gu %VM_USER% -gp %VM_PASS% CopyFileFromGuestToHost "%VM_VMX%" "%GUEST_TEST_DIR%\r133_probe.txt" "%REPO%\tests\r133_probe_out.txt"
exit /b %ERRORLEVEL%
