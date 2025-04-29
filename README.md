# 📦 Packalyzer - PE File Packing and Obfuscation Detection Tool
### 🎯 Purpose
Packalyzer is a Python-based tool designed for analyzing Windows PE (Portable Executable) files to determine:

- Whether a file is packed (compressed or encrypted with a packer),

- Whether a file shows signs of obfuscation (techniques used to evade static analysis).

The tool uses multiple techniques:

- Entropy Analysis: Checks the randomness of each PE section (high entropy often signals packing).

- Import Table Analysis: Packed or obfuscated files often have missing or minimal import tables.

- YARA Rules: Scans the binary using YARA rules to detect known packers like UPX.

- Capstone Disassembly: Detects abnormal control flow, such as excessive jump instructions (jmp), which often indicates obfuscation.

It is especially useful for cybersecurity students, malware analysts, reverse engineers, and digital forensics professionals.

### 📚 Academic Context
This tool was created as part of a final exam project for the Master of Science in Cybersecurity program at Utah Valley University.

The focus of the project is to demonstrate proficiency in:

- Static malware analysis,

- Binary analysis automation,

- Usage of industry-standard libraries like Capstone, YARA, and PEfile.

### ⚠️ Disclaimer

This tool is intended for **educational** and **testing** purposes only.

Use it only on files that you are authorized to analyze.  
Unauthorized analysis, distribution, or reverse engineering of third-party software may violate software licenses and/or laws.

The author and Utah Valley University are **not responsible** for any misuse of this tool. Always ensure you are in compliance with applicable local, state, federal, and international laws.

