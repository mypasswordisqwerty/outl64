@echo off
net session >nul 2>&1
if %errorLevel% == 0 goto admin
echo Administrator rights required.
pause
exit /b 1
:admin

SET RUNPATH=%~dp0 
SET IDIR=%RUNPATH:~0,-2%

echo %IDIR% 

echo PYTHON check...
if exist c:\python27 goto endpython
echo installing python
msiexec /i "%IDIR%\python-2.7.13.msi" /quiet
:endpython


echo GIT check...
if exist .\git goto endgit
echo installing git
"%IDIR%\7za" x -ogit "%IDIR%\PortableGit-2.12.2.2-64-bit.7z.exe"
cd git
call post-install.bat
cd ..
:endgit

echo OFFICE check...
if exist %IDIR%\OFFICE2013 goto endunpack
echo unpacking office
"%IDIR%\Microsoft.Office.2013x64.Standard.v2015.11.exe" -y -nr | more
move %WINDIR%\Temp\OFFICE2013 %IDIR%\

:endunpack
if exist "c:\program files\microsoft office" goto endoffice
echo installing office
"%IDIR%\OFFICE2013\OfficeX64\Setup.exe" /adminfile ..\..\outl.msp | more
rem echo KMS'ing office
rem "%IDIR%\OFFICE2013\AutorunHelper.exe" /KMS | more
echo outlook firstrun
start "" "%ProgramFiles%\Microsoft Office\OFFICE15\Outlook.exe"
timeout 30
echo killing outlook
taskkill /F /IM outlook.exe /T
:endoffice

echo VCREDIST check...
if exist "%WINDIR%\system32\mfc140u.dll" goto endredist
echo installing vcredist
"%IDIR%\vc_redist.x64.exe" /quiet  /norestart | more
:endredist

echo REPOSITORY check...
if exist .\outl64 goto repend
echo cloning git repository
git\git-bash.exe -c "git clone https://somegit/outl64 || read"
goto repend
:repend

echo UPDATE check...
if exist .\update.cmd goto update
echo creating update.cmd
echo cd outl64 > .\update.cmd
echo echo updating git repository >> .\update.cmd
echo ..\git\git-bash.exe -c "GIT_SSL_NO_VERIFY=true git pull || read" >> .\update.cmd
echo echo updating outl64 >> .\update.cmd
echo rem c:\python27\python.exe install.py >> .\update.cmd
echo cd .. >> .\update.cmd
echo c:\python27\python.exe outl64\fuzzer\start.py >> .\update.cmd

:update
echo installing fuzzer...
cd outl64
c:\python27\python.exe install.py

if "%1"=="" goto noid
echo hostId=%1 >> pyoutconf.py
:noid
cd ..
echo INSTALLED

c:\python27\python.exe outl64\fuzzer\start.py
