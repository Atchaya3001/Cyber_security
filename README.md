
## MALWARE  ANALYSIS

Malware Analysis (MA.py) is a web-based tool designed for cybersecurity professionals to perform comprehensive malware analysis and cyber attribution. It integrates multiple analysis tools such as YARA, Radare2, and VirusTotal, enabling in-depth examination of files and detailed reporting.
## Features

- Zen scan : Upload custom YARA rules to scan files for known malicious patterns, and receive detailed match information.
- Graph insight : Conduct advanced static analysis, generate control flow graphs (CFGs), and export results for further investigation.
- Threat Scan : Check files, URLs, domains, and IP addresses against VirusTotal’s database, with automatic report sharing.
-  String extraction : string extraction from a malicious file is a fundamental technique in malware analysis that involves extracting human-readable text (or "strings") from a binary file, such as an executable or a DLL. 

- Code breaker : code breaker is a technique in this project that involves translating binary code (machine code) into human-readable assembly language. 

- Email Reporting : Receive detailed analysis reports via email, with customizable templates.


## Installation
  - Python 3.7+: Ensure you have Python 3.7 or higher installed.
- pip: The Python package manager.


    
## Steps

   
  1. Clone the Repository:
   ```bash
      git clone https://github.com/kousalyadev/malware.git
   ```
  2. Navigate to the Project Directory:
   ```bash
      cd Malware-Analysis
   ```
  3. Install Required Dependencies:
   ```bash
      pip install -r requirements.txt
   ```
  4. Configure the Application:
  
        Modify the `config.py` file to set up paths for YARA rules, your VirusTotal API key, and email settings.

  5. Run the Application:
   ```bash
      python MA.py
   ```
  6. Access the Web Interface:
     Open your browser and go to `http://127.0.0.1:__user defined port___`.

## Usage

- ZEN Scan: Upload a file and specify the YARA rule file path to initiate a scan. Results are displayed in the interface and sent via email.
- Graph insight : Upload a file for static analysis and view control flow graphs directly on the interface.
- Threat scan : Enter a file, URL, domain, or IP address.
- String Miner : upload a file and its extracts the string from the file.
- Code breaker : upload a file and it breaks the file and display the malicious code hidden within the executable.


## Contributing

Contributing

Contributions are welcome! To contribute:

      1.Fork the repository.
      2.Create a new branch (git checkout -b feature-branch).
      3.Make and commit your changes (git commit -m 'Add some feature').
      4.Push to the branch (git push origin feature-branch).
      5.Create a Pull Request.


License:

   This project is licensed under the MIT License - see the LICENSE file for details.

Contact:

   For support or inquiries, contact Atchaya Arumugam at atchayaarumugam2004@gmail.com.

Acknowledgments:

   1.Graph insight: Open-source software for reverse engineering.

   2.ZEN scan: Tool for identifying and classifying malware samples.

   3.Threat Scan: Online service for analyzing files and URLs for viruses.


GitHub Repository:

  Find the source code at Malware Analysis & Cyber Attribution on GitHub: https://github.com/Atchaya3001/cyber_security.


