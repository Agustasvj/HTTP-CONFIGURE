# HTTP-CONFIGURE SSH Tunnel

A Python-based SSH tunneling tool that enables secure connections through HTTP proxies. This tool is designed to provide a reliable and secure way to establish SSH connections through proxy servers.

## Features

- SSH tunneling through HTTP proxy
- Custom SSH algorithm selection
- Detailed connection logging
- Support for PuTTY-style connections
- Configurable timeout settings
- Robust error handling
- Cross-platform compatibility (Windows & Linux)

## Requirements

- Python 3.7 or higher
- Required Python packages (see requirements.txt):
  - paramiko>=3.4.0
  - pysocks>=1.7.1
  - dnspython>=2.6.0

## Installation

### Windows

1. Clone the repository: 
git clone https://github.com/Agustasvj/HTTP-CONFIGURE.git
  cd 
cd HTTP-CONFIGURE


2. Set up virtual environment:
  
    python -m venv venv
    venv\Scripts\activate


3. Install requirements:
     
    pip install -r requirements.txt

   
### Linux

1. Clone the repository:
   
     git clone https://github.com/Agustasvj/HTTP-CONFIGURE.git
     cd HTTP-CONFIGURE

2. Install system dependencies (Ubuntu/Debian):
     sudo apt-get update
     sudo apt-get install python3-dev python3-pip build-essential libssl-dev        libffi-dev

3. Set up virtual environment:
     bash
   python3 -m venv venv
   source venv/bin/activate


4. Install requirements:
   
    bash
    pip install -r requirements.txt


5. Make the script executable:

   bash
   chmod +x new.py


## Usage

Run the script:

  bash
  python new.py # Windows
  python3 new.py # Linux



The tool will:
1. Start the SSH service
2. Connect to the specified HTTP proxy
3. Establish an SSH tunnel
4. Handle authentication
5. Maintain the connection

## Configuration

Default settings:
- SSH Version: PuTTY_Release_0.76
- Default timeout: 30 seconds
- Supported algorithms:
  - KEX: diffie-hellman-group14-sha256
  - Cipher: aes128-ctr
  - MAC: hmac-sha2-256
  - Key: rsa-sha2-256

## Troubleshooting

Common issues and solutions:

1. Connection Timeout
   - Verify proxy settings
   - Check internet connection
   - Ensure proxy server is accessible

2. Authentication Failures
   - Verify SSH credentials
   - Check SSH server accessibility
   - Verify proxy authentication requirements

3. Permission Issues
   - Check file permissions (Linux)
   - Run with appropriate privileges

## Debug Logging

The tool provides detailed logging information during connection attempts:
- SSH service status
- Proxy connection details
- Authentication progress
- Key exchange information
- Error messages

## Security

- Uses secure SSH algorithms
- Implements proper key exchange
- Supports encrypted connections
- Handles authentication securely

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and legitimate use only. Users are responsible for complying with all applicable laws and regulations.

## Author

Agustas VJ

## Support

For issues, questions, or contributions, please:
1. Open an issue on GitHub
2. Submit a pull request
3. Contact through GitHub

## Contact
 murithijsvj@gmail.com

---
**Note**: Always ensure you have permission to use any proxy or SSH servers you connect to.
