param([Parameter(Mandatory=$true)][ValidateSet("x86","x64","arm64")][string]$Architecture)
$ErrorActionPreference = "Stop"
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class SystemModule {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryExW(string name, IntPtr file, uint flags);
    [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    public static extern uint GetModuleFileNameW(IntPtr h, StringBuilder path, int max);
    [DllImport("kernel32.dll")] public static extern bool FreeLibrary(IntPtr h);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool IsWow64Process2(IntPtr proc, out ushort guest, out ushort native);
}
'@
$guest = [UInt16]0
$native = [UInt16]0
if (-not [SystemModule]::IsWow64Process2([SystemModule]::GetCurrentProcess(), [ref]$guest, [ref]$native)) { throw "IsWow64Process2 failed" }
$processMachine = $native
if ($guest -ne 0) { $processMachine = $guest }
$codes = @{x86=0x14c;x64=0x8664;arm64=0xaa64}
if ($processMachine -ne $codes[$Architecture]) { throw "Expected $Architecture, observed $processMachine" }
$spec = Get-Content -Raw (Join-Path $PSScriptRoot "names.json") | ConvertFrom-Json
$modules = @()
foreach ($module in $spec.modules.PSObject.Properties) {
    $h = [SystemModule]::LoadLibraryExW($module.Name, [IntPtr]::Zero, 0x800)
    $loadError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $present = @()
    $missing = @()
    $filename = ""
    $digest = ""
    if ($h -ne [IntPtr]::Zero) {
        try {
            $path = [Text.StringBuilder]::new(32768)
            if ([SystemModule]::GetModuleFileNameW($h, $path, $path.Capacity) -eq 0) { throw "GetModuleFileNameW failed" }
            $filename = $path.ToString()
            $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $filename).Hash.ToLowerInvariant()
            foreach ($export in $module.Value) {
                if ([SystemModule]::GetProcAddress($h, $export) -ne [IntPtr]::Zero) { $present += $export }
                else { $missing += $export }
            }
            $loadError = 0
        } finally { [void][SystemModule]::FreeLibrary($h) }
    } else { $missing = @($module.Value) }
    $modules += [ordered]@{module=$module.Name; file=$filename; sha256=$digest; present=$present; missing=$missing; load_error=$loadError}
}
if (-not ($modules | Where-Object { $_.present.Count -gt 0 })) { throw "No named SDK export was observed" }
$result = [ordered]@{architecture=$Architecture; os_build=[Environment]::OSVersion.Version.ToString(); pointer_size=[IntPtr]::Size; native_machine=$native; process_machine=$processMachine; revision=$spec.revision; modules=$modules}
$result | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $PSScriptRoot ("observed-"+$Architecture+".json"))
