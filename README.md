# HVCI Utils - Mi+vbd disabler and much more


this simple FOSS powershell scripts main feature is  disabling / enabling the memory integrity and vdb(vulnerable driver blocklist) **without needing to restart the pc twice** (like you normally would).

<img width="484" height="1363" alt="image" src="https://github.com/user-attachments/assets/e6481520-cdb5-491f-8943-85af8962b598" />


## Requirements
 - Windows 10/11
 - Powershell 5.1+
 - Windows Terminal (auto launches if installed)
 - Run as administrator (Auto-Evalates)
 
## Usage
- right-click hvci-utils.ps1 → run with powershell
- or from an elevated terminal:
```
powershell -ExecutionPolicy Bypass -File hvci-utils.ps1
```

## Features
- disable / enable memory integrity (HVCI) + vulnerable driver blocklist in one restart instead of two
- full windows security overview
- rebooting into uefi / bios
- rebooting into windows recovery mode
- toggling hyper-v on / off

## How it works
this works by simply changing the relevant registry keys for both memory integrity (HypervisorEnforcedCodeIntegrity) and the vulnerable driver blocklist (VulnerableDriverBlocklistEnable) in a single session, before any restart occurs.

this way the kernel picks up both changes on the same boot cycle.

the other features are simple commands , which can all theoretically be done without the need of a script.




## License

HVCI Utils is an open-source project available under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) License.
