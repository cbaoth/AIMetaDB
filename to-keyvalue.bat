@echo off

@rem print to console
@rem python %~dp0\main.py --mode TOKEYVALUE --value-substitution "[\n]" "\n  " %*
python %~dp0\main.py --mode TOKEYVALUE --key-substitution "^(.*)$" "\n== \1 ==\n  " %*
@rem copy to clipboard
@rem python %~dp0\main.py --mode TOKEYVALUE %* --value-substitution "[\n]" "\n  " | clip
python %~dp0\main.py --mode TOKEYVALUE --key-substitution "$" "\t" %* | clip

pause
