@echo off

:: python %~dp0\main.py --mode TOJSON %*
python %~dp0\main.py --mode TOJSON %* | clip

:: pause
