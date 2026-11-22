@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 启动嗅探器 http://localhost:8000
echo 提示：抓包需要管理员权限（右键"以管理员身份运行"本脚本或 PowerShell）
python app.py
pause
