# ForShops
A proof-of-concept fileless DCOM Lateral Movement technique using trapped COM objects

## Description

This project contains C++ source code for reflectively loading and executing a .NET assembly in a remote computer's WaaS Medic Service svchost.exe process for lateral movement over DCOM.

The technique abuses the trapped COM object bug class originally discovered by [James Forshaw](https://x.com/tiraniddo) of Google Project Zero.

For detailed information, please see the accompanying Security Intelligence blog [post]([https://](https://securityintelligence.com/x-force/fileless-lateral-movement-with-trapped-com-objects/) by [Dylan Tran](https://x.com/d_tranman) and [Jimmy Bayne](https://x.com/bohops) of IBM X-Force Red.

## Usage

- Compile with Visual Studio
- Run with the following command under a privileged context:
```
forshops.exe [target machine ] [c:\\path\\to\\assembly\\to\\load]
```

## References

- [Windows Bug Class: Accessing Trapped COM Objects with IDispatch](https://googleprojectzero.blogspot.com/2025/01/windows-bug-class-accessing-trapped-com.html) by James Forshaw
- [IE11SandboxEscapes Project](https://github.com/tyranid/IE11SandboxEscapes) by James Forshaw

## License
This project is licensed under the **GNU General Public License v3.0**.  
See the [LICENSE](LICENSE) file for details.

This project includes code from [IE11SandboxEscapes](https://github.com/tyranid/IE11SandboxEscapes) by James Forshaw, 
licensed under GNU General Public License v3.0. See the project [license](https://github.com/tyranid/IE11SandboxEscapes/blob/master/LICENSE) for details.
