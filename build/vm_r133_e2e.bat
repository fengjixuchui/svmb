@echo off
if exist "%~dp0vmenv.bat" call "%~dp0vmenv.bat"
rem r133: mem_crypt e2e. Driver+ctl+target all changed this round.
rem Flow: stop svc -> push 3 artifacts + suite -> set knobs (NptEnable,
rem ReadVmEnable - production gate ships readvm OFF by default) -> start
rem svc (AutoStart enters virtualization at load) -> run suite -> done.
rem The guest bat runs the full cycle, the hold leg and the unload leg.
set VR="%VMRUN%" -T ws -gu %VM_USER% -gp %VM_PASS%
%VR% runProgramInGuest "%VM_VMX%" "C:\Windows\System32\cmd.exe" "/c sc stop svmb >> %GUEST_DESKTOP%\svmb_steps.log 2>&1 < NUL" >nul 2>&1
%VR% runProgramInGuest "%VM_VMX%" "C:\Windows\System32\cmd.exe" "/c ping -n 5 127.0.0.1 >nul < NUL" >nul 2>&1
%VR% CopyFileFromHostToGuest "%VM_VMX%" "%REPO%\x64\Debug\svmb.sys" "%GUEST_TEST_DIR%\svmb.sys"
if errorlevel 1 exit /b 1
%VR% CopyFileFromHostToGuest "%VM_VMX%" "%REPO%\x64\Debug\svmbctl.exe" "%GUEST_TEST_DIR%\svmbctl.exe"
if errorlevel 1 exit /b 1
%VR% CopyFileFromHostToGuest "%VM_VMX%" "%REPO%\x64\Debug\mcrypt_target.exe" "%GUEST_TEST_DIR%\mcrypt_target.exe"
if errorlevel 1 exit /b 1
%VR% CopyFileFromHostToGuest "%VM_VMX%" "%REPO%\build\guest_r133_e2e.bat" "%GUEST_TEST_DIR%\r133_e2e.bat"
if errorlevel 1 exit /b 1
call "%~dp0vm_reg_add_npt.bat"
call "%~dp0vm_reg_readvm.bat" 1
rem start the service (DriverEntry + AutoStart + NptEnable=1)
%VR% runProgramInGuest "%VM_VMX%" "C:\Windows\System32\cmd.exe" "/c sc start svmb >> %GUEST_DESKTOP%\svmb_steps.log 2>&1 < NUL" >nul 2>&1
%VR% runProgramInGuest "%VM_VMX%" "C:\Windows\System32\cmd.exe" "/c ping -n 6 127.0.0.1 >nul < NUL" >nul 2>&1
rem run the suite (its whole output lands in the steps log)
%VR% runProgramInGuest "%VM_VMX%" "C:\Windows\System32\cmd.exe" "/c %GUEST_TEST_DIR%\r133_e2e.bat >> %GUEST_DESKTOP%\svmb_steps.log 2>&1 < NUL"
exit /b %ERRORLEVEL%
