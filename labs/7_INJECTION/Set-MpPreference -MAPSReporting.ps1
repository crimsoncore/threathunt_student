Set-MpPreference -MAPSReporting

Get-MpComputerStatus

AMEngineVersion                 : 1.1.17600.5
AMProductVersion                : 4.18.2010.7
AMRunningMode                   : Normal
AMServiceEnabled                : True
AMServiceVersion                : 4.18.2010.7

Get-MpPreference | select-object DisableRealtimeMonitoring, SubmitSamplesConsent, MAPSReporting, ExclusionPath, ExclusionExtension | fl
Get-MpComputerStatus | select-object AntivirusEnabled, AntivirusSignatureLastUpdated, RealTimeProtectionEnabled, OnAccessProtectionEnabled | fl
Update-MpSignature
get-command -module Defender
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' | Select-Object -First 1 -ExpandProperty Message
Update-MpSignature

get-computerinfo
18362.1.amd64fre.19h1_release.190318-1202
10.0.18363

Set-MpPreference -ExclusionPath C:\Windows\Temp
Set-MpPreference -ExclusionExtension exe
Remove-MpPreference -ExclusionPath C:\Windows\Temp

Get-MpPreference | select-object ExclusionExtension 