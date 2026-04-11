@echo off
:: Launch 20 hidden instances of benign applications
for /L %%i in (1,1,20) do (
    start /B "" "C:\Windows\System32\calc.exe"
    start /B "" "C:\Windows\System32\notepad.exe"
)
echo Process count inflated by 40 instances.
