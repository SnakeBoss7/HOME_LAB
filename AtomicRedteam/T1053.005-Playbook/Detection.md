# Attack Execution: T1053.005

##  Prerequisites
- **Atomic Red Team** installed on the victim machine.
- **PowerShell** running as Administrator.

##  Execution Steps

### 1. Scheduled Task via cmd
 Status:   DETECTED
This test creates a scheduled task named "AtomicTask" that spawns a command prompt, and this is a persistant scheduled task.

**Command:**
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

**What happens:**
1.  `schtasks.exe` is executed.
2.  A new task "AtomicTask" is registered.
3.  The task is set to run a command (often `echo` or `calc.exe` for testing).

**Verification:**
SPL for splunk :
```cmd
For dashboard

index=sysmon sourcetype="Win10" EventCode=1 Image=*schtasks*
| eval Type=case(
    like(CommandLine, "%OnLogon%"), "OnLogon",
    like(CommandLine, "%OnStartup%"), "OnStartup",
    true(), "Other"
)
| stats 
    values(Image) as Images
    values(CommandLine) as Commands
    count as Count
  by Type
```

For alert

```alert
index=sysmon sourcetype="Win10" EventCode=1 Image=*schtasks*
```
**Results**

![#test 1](img/T1053.005_1.png)

### 2. Scheduled Task via PWSH
This test creates a scheduled task named "AtomicTask" that spawns a command prompt.
Status:  PARTIALLY DETECTED
**Command:**
```powershell
#atomic
Invoke-AtomicTest T1053.005 -TestNumbers 2
```

**What happens:**
1.  `powershell.exe` is executed.
2.  A new task "AtomicTask" is registered.
3.  The task is set to run a command (often `echo` or `calc.exe` for testing).

**Verification:**
SPL for splunk :
 - For dashboard 
```cmd

index=sysmon sourcetype="Win10" EventCode=1 CommandLine="*Powershell.exe*"
| sort - _time
```

- For alert

```alert
index=sysmon sourcetype="Win10" EventCode=1 CommandLine="*PS_ScheduledTask*" CommandLine="*Invoke-CimMethod*"
```
**Results**

![#test 1](img/T1053.005_1.png)


### 3. Scheduled Task via WMI(Window Management Instrumentation)
This test creates a scheduled task named "AtomicTask" that spawns a command prompt.
Status:  PARTIALLY DETECTED
**Command:**
```powershell
#atomic
Invoke-AtomicTest T1053.005 -TestNumbers 6
#manual
"$xml = [System.IO.File]::ReadAllText('C:\Users\INSAEN\Downloads\atomic-red-team\atomics\T1053.005\src\T1053_005_WMI.xml');
 Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace 'Root\Microsoft\Windows\TaskScheduler' -MethodName 'RegisterByXml' -Arguments @{ Force = $true; Xml = $xml }"
```

**What happens:**
1.  `powershell.exe` is executed which calls PS_SheduledTask which directly access the Task Scheduler using WMI .
2.  A new task "AtomicTask" is registered.
3.  The task is set to run a command (often `echo` or `calc.exe` for testing).

**Verification:**
SPL for splunk :
 - For dashboard 
```cmd

index=sysmon sourcetype="Win10" EventCode=1 CommandLine="*PS_ScheduledTask*"  CommandLine="*Invoke-CimMethod*"
| table EventCode ,Image,CommandLine ,_time
| sort - _time
```

- For alert

```alert
index=sysmon sourcetype="Win10" EventCode=1 CommandLine="*PS_ScheduledTask*" CommandLine="*Invoke-CimMethod*"
```
**Results**

![#test 1](img/T1053.005_1.png)


# NOTE 
### As this attack used mumtiple execution under the same existing poweshell, it is not detected only the first process execution is detectd 
- Example as in #test 2 and 3 which internally involves

```cmd
$Action = New-ScheduledTaskAction -Execute "calc.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTask -InputObject $object
```

 - AND

```cmd
$xml = [System.IO.File]::ReadAllText("#{xml_path}")
Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace "Root\Microsoft\Windows\TaskScheduler" -MethodName "RegisterByXml" -Arguments @{ Force = $true; Xml =$xml; }
```

### but they are not fully detectable with full information like in the 2nd Test Sysmon was able to Capture only the first process execution i.e 

`Image` - `	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
`CommandLine` - `"powershell.exe" & {$Action = New-ScheduledTaskAction -Execute \""calc.exe\""`
