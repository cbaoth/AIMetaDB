@echo off

:: python %~dp0\main.py --mode TOCSV %*
python %~dp0\main.py --mode TOCSV %* | clip

rem pause
