@echo off

:: Save current code page
@REM for /f "tokens=2 delims=:" %%a in ('chcp') do set ORIGINAL_CP=%%a
@REM echo %ORIGINAL_CP%

:: Set console encoding to UTF-8
@REM chcp 65001 > nul

:: Run Python once for console output and once for clipboard output
@REM python %~dp0\main.py --mode TOKEYVALUE --key-substitution "$" "\n└── " %*
@REM python %~dp0\main.py --mode TOKEYVALUE --key-substitution "^(.*)$" "\n+\1\n'-- " %*
python %~dp0\main.py --mode TOKEYVALUE --key-substitution "^(.*)$" "\n[\1] ->\n  " %*
python %~dp0\main.py --mode TOKEYVALUE --key-substitution "$" "\t" %* | clip

:: Restore original code page
@REM chcp %ORIGINAL_CP% > nul
@REM chcp 437 > nul

pause
goto :eof

:: Examples
:: - Print to console
@REM python %~dp0\main.py --mode TOKEYVALUE --value-substitution "[\n]" "\n  " %*
@REM python %~dp0\main.py --mode TOKEYVALUE --key-substitution "^(.*)$" "\n== \1 ==\n  " %*
@REM python "%~dp0\main.py" --mode TOKEYVALUE --key-substitution "$" "n└── " %*
:: - Copy to clipboard
@REM copy to clipboard
@REM python %~dp0\main.py --mode TOKEYVALUE %* --value-substitution "[\n]" "\n  " | clip
@REM python "%~dp0\main.py" --mode TOKEYVALUE --key-substitution "$" "\t" "%*" | clip

:eof
