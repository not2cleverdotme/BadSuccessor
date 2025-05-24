# Network Security Tools

A collection of enhanced network security and penetration testing tools written in Python.

## Tools Overview

### 1. TCP/UDP Clients and Server
- `client_tcp.py`: Enhanced TCP client with SSL support and improved error handling
- `client_udp.py`: Enhanced UDP client with retry mechanism and improved reliability
- `server_tcp.py`: Multi-threaded TCP server with SSL support and connection management

### 2. Netcat Replacement (`netcat.py`)
An enhanced version of netcat with additional features:
- SSL/TLS support
- File upload/download capabilities
- Secure command execution
- Interactive shell mode
- Improved error handling and logging

### 3. SSH Command Client (`ssh_cmd.py`)
Advanced SSH client with features:
- Key-based and password authentication
- Command execution
- File transfer capabilities
- Connection retry mechanism
- Detailed logging

### 4. Hidden WiFi Scanner (`hiddenwifi.py`)
WiFi network scanner focusing on hidden networks:
- Channel hopping
- Signal strength monitoring
- Probe request/response analysis
- JSON output support
- Comprehensive logging

### 5. MAC Address Spoofer (`macspoof.py`)
MAC address manipulation tool with features:
- Random MAC generation
- Vendor prefix preservation
- Common vendor MAC support
- Interface validation
- Backup and restore capabilities

### 6. Reconnaissance Tool (`recon.py`)
Comprehensive target reconnaissance tool:
- DNS enumeration
- HTTP header analysis
- SSL/TLS certificate inspection
- WHOIS lookup
- GeoIP information
- Security headers check
- Multi-threaded operation

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Python_Projects.git
cd Python_Projects
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage Examples

### TCP Client
```bash
# Connect to a server
python client_tcp.py example.com -p 443 --ssl

# Send data with custom timeout
python client_tcp.py example.com -p 80 -t 10 -d "Hello, Server"
```

### UDP Client
```bash
# Basic UDP communication
python client_udp.py -H 192.168.1.100 -p 5000 -m "Test message"

# With retry mechanism
python client_udp.py -H 192.168.1.100 -p 5000 --retries 3
```

### TCP Server
```bash
# Start basic server
python server_tcp.py -p 8080

# Start SSL server
python server_tcp.py -p 443 --ssl --cert cert.pem --key key.pem
```

### Netcat Replacement
```bash
# Command shell
python netcat.py -t 192.168.1.100 -p 5555 -l -c

# File upload
python netcat.py -t 192.168.1.100 -p 5555 -l -u file.txt

# SSL connection
python netcat.py -t 192.168.1.100 -p 5555 --ssl --cert cert.pem
```

### SSH Command Client
```bash
# Execute command
python ssh_cmd.py -H example.com -u user -c "ls -la"

# Upload file
python ssh_cmd.py -H example.com -u user --upload local.txt remote.txt

# Using key authentication
python ssh_cmd.py -H example.com -u user -k ~/.ssh/id_rsa
```

### Hidden WiFi Scanner
```bash
# Basic scan
sudo python hiddenwifi.py -i wlan0

# Channel hopping scan
sudo python hiddenwifi.py -i wlan0 --hop

# Save results
sudo python hiddenwifi.py -i wlan0 -o results.json
```

### MAC Address Spoofer
```bash
# Random MAC
sudo python macspoof.py -i eth0

# Specific MAC
sudo python macspoof.py -i eth0 -m 00:11:22:33:44:55

# Preserve vendor
sudo python macspoof.py -i eth0 --preserve-vendor
```

### Reconnaissance Tool
```bash
# Basic scan
python recon.py example.com

# With API key
python recon.py example.com -k your_api_key

# Save results
python recon.py example.com -o results.json
```

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