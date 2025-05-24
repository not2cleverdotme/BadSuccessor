# BadSuccessor



## Security Considerations

1. These tools are for educational and testing purposes only
2. Always obtain proper authorization before testing on networks or systems
3. Some tools require root/administrator privileges
4. Use SSL/TLS when possible for secure communications
5. Be cautious with command execution features
6. Review and understand the code before running

## Requirements

- Python 3.8+
- See `requirements.txt` for package dependencies
- Root/Administrator privileges for some tools
- Network interface with monitor mode support (for WiFi tools)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

These tools are for educational and testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by these tools.

# BadSuccessor Permission Scanner

This PowerShell script is designed to help security professionals and system administrators identify potential BadSuccessor attack vectors in their Active Directory environment. The script is based on the BadSuccessor privilege escalation vulnerability discovered in Windows Server 2025, as documented by [Akamai's research team](https://github.com/akamai/BadSuccessor).

## About BadSuccessor

BadSuccessor is a privilege escalation vulnerability in Windows Server 2025 that allows attackers to escalate privileges by abusing the delegated Managed Service Account (dMSA) feature. According to Akamai's research, this vulnerability:

- Works in default configurations
- Allows attackers to act with privileges of any user without modifying the target object
- Affects approximately 91% of environments where non-admin users have the required permissions
- Currently has no available patch from Microsoft

## Script Features

The `Get-BadSuccessorOUPermissions.ps1` script provides the following capabilities:

- Scans all Organizational Units (OUs) for vulnerable permissions
- Identifies principals that could potentially execute a BadSuccessor attack
- Maps vulnerable OUs to their corresponding security principals
- Provides simulation capabilities to demonstrate attack paths
- Excludes built-in privileged accounts from results
- Supports verbose logging for detailed analysis

## Prerequisites

- Windows PowerShell 5.1 or later
- Active Directory PowerShell Module (RSAT Tools)
- Domain User Rights
- Read access to Active Directory

## Usage

### Basic Scan
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

### Simulation Mode
```powershell
.\Get-BadSuccessorOUPermissions.ps1 -SimulateAttack
```

### Target Specific OU with Simulation
```powershell
.\Get-BadSuccessorOUPermissions.ps1 -SimulateAttack -TargetOU "OU=IT,DC=contoso,DC=com"
```

### Detailed Logging
```powershell
.\Get-BadSuccessorOUPermissions.ps1 -Verbose
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-SimulateAttack` | Enables attack path simulation mode without making actual changes |
| `-TargetOU` | Specifies a particular OU for simulation (DN format) |
| `-Force` | Bypasses confirmation prompts in simulation mode |
| `-Verbose` | Enables detailed logging of all operations |

## Output

The script provides:

1. Without `-SimulateAttack`:
   - List of security principals with required permissions
   - Count of vulnerable OUs per principal
   - First vulnerable OU for each principal

2. With `-SimulateAttack`:
   - Step-by-step simulation of the attack path
   - Permission validation results
   - dMSA creation simulation
   - Privilege escalation steps

## Security Note

This tool is intended for:
- Security assessment and testing only
- Identifying potential security risks
- Improving Active Directory security posture

Always obtain proper authorization before running security tests in your environment.

## Acknowledgments

This script is based on the BadSuccessor vulnerability research by Akamai Technologies Inc. For more information about the original research, visit [Akamai's BadSuccessor Repository](https://github.com/akamai/BadSuccessor).

## License

This script follows the same licensing terms as the original BadSuccessor project by Akamai Technologies Inc.

## Disclaimer

This tool is provided for legitimate security testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool in any environment. 