function Invoke-Sh
{

    [CmdletBinding()]
    Param (
        [String]
        $Command = "-c All"

    )
    $RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($base64binary))
    [SharpH0und3.SharpH0und]::InvokeSharpH0und($Command.Split(" "))
  
}