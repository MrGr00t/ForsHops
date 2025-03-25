# ForShops
A proof-of-concept fileless DCOM Lateral Movement technique using trapped COM objects

## Description

This project contains C++ source code for reflectively loading and executing a .NET assembly in a remote computer's WaaS Medic Service svchost.exe process for DCOM lateral movement.

The technique abuses the trapped COM object bug class originally discovered by [James Forshaw](https://x.com/tiraniddo) of Google Project Zero.

For detailed information, please see the accompanying Security Intelligence blog [post](https://www.ibm.com/think/news/fileless-lateral-movement-trapped-com-objects) by [Dylan Tran](https://x.com/d_tranman) and [Jimmy Bayne](https://x.com/bohops) of IBM X-Force Red.

## Usage

- Compile with Visual Studio
- Run with the following command under a privileged context:
```
forshops.exe [target machine] [c:\\path\\to\\assembly\\to\\load]
```

## Defensive Recommendations

The [detection guidance](https://x.com/SBousseaden/status/1896527307130724759) proposed by [Samir Bousseaden](https://x.com/SBousseaden) is applicable for this lateral movement technique:
- Detecting CLR load events within the svchost.exe process of WaaSMedicSvc
- Detecting Registry manipulation (or creation) of the following key: HKLM\SOFTWARE\Classes\CLSID\{0BE35203-8F91-11CE-9DE3-00AA004BB851}\TreatAs (TreatAs key of StandardFont CLSID)

We also recommend implementing the following additional controls:
- Detecting DACL manipulation of HKLM\SOFTWARE\Classes\CLSID\{0BE35203-8F91-11CE-9DE3-00AA004BB851}
- Hunting for the presence of enabled OnlyUseLatestCLR and AllowDCOMReflection values in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework
- Enabling the host-based firewall to restrict DCOM ephemeral port access where possible

Use the following proof-of-concept YARA rule to detect the standard ForsHops.exe executable:
```
rule Detect_Standard_ForsHops_PE_By_Hash
{
    meta:
        description = "Detects the standard ForShops PE file by strings"
        reference = "GitHub Project: https://github.com/xforcered/ForsHops/"
    strings:
        $s1 = "System.Reflection.Assembly, mscorlib" wide
        $s2 = "{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}" wide
        $s3 = "{34050212-8AEB-416D-AB76-1E45521DB615}" wide
        $s4 = "GetType" wide
        $s5 = "Load" wide
    condition:
        all of them
}
```

## References

- [Windows Bug Class: Accessing Trapped COM Objects with IDispatch](https://googleprojectzero.blogspot.com/2025/01/windows-bug-class-accessing-trapped-com.html) by James Forshaw
- [IE11SandboxEscapes Project](https://github.com/tyranid/IE11SandboxEscapes) by James Forshaw

## License
This project is licensed under the **GNU General Public License v3.0**.  
See the [LICENSE](LICENSE) file for details.

This project includes code from [IE11SandboxEscapes](https://github.com/tyranid/IE11SandboxEscapes) by James Forshaw, 
licensed under GNU General Public License v3.0. See the project [license](https://github.com/tyranid/IE11SandboxEscapes/blob/master/LICENSE) for details.
