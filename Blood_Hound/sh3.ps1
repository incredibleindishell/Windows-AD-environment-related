function Invoke-3
{

    [CmdletBinding()]
    Param (
        [String]
        $Com = "-cb0xall"

    )
    $RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($base64binary))
    [SharpH0und3.SharpH0und]::InvokeSharpH0und($Com.Split("b0x"))
  
}