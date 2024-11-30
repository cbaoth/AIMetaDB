@echo off

@rem print to console
python %~dp0\main.py --mode TOKEYVALUE --value-substitution "[\n]" "\n  " %*
@rem copy to clipboard
python %~dp0\main.py --mode TOKEYVALUE %* --value-substitution "[\n]" "\n  " | clip

pause
