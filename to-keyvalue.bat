@echo off

python %~dp0\main.py --mode TOKEYVALUE %*
python %~dp0\main.py --mode TOKEYVALUE %* | clip

pause
