@echo off
chcp 65001 >nul
setlocal
set ICON=
if exist cfs.ico set ICON=--icon cfs.ico --add-data "cfs.ico;."
python -m pip install -r requirements.txt pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name CloudFlareScan %ICON% cloudflare_scan.py
copy /Y LICENSE dist\LICENSE
echo.
echo Done: dist\CloudFlareScan.exe  (distribute together with dist\LICENSE)
pause
