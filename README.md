# 📦 Packanalyzer - PE File Packing and Obfuscation Detection Tool
### 🎯 Purpose
Packanalyzer is a Python-based tool designed for analyzing Windows PE (Portable Executable) files to determine:

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

### Run Analysis Tool:

- Once the environment is set up and the dependencies are installed, you can run the analysis script to examine the packed executable. You need to make sure you have the packing.exe file. This file is inside of the finalexample(1).7zip.

- On macOS or Windows, open your terminal (macOS) or Command Prompt (Windows) and run:
```
python3 ./Main/analyzer.py ./Main/packing.exe

```
- This command assumes your script (analyzer.py) is in the Main folder, and the packing.exe file you want to analyze is in the same folder.

- The output will show the analysis of the packing.exe file (whether it’s packed, obfuscated, its imports, and more).

### Run PackInspector on Windows or Mac:

```
python3 .\packinspector\packinspector.py "C:\path\to\your\packing.exe" 

OR

python3 ./packinspector/packinspector.py ./Main/packing.exe

```
- PackInspector will provide you with a summary of its findings (such as packer information, whether it's obfuscated, entropy analysis, etc.). You can take a screenshot of the results as part of your documentation.

### Combining Python Tool and PackInspector:

Once both tools are set up on your system, you can use the Python analysis tool to analyze the packed executable and then use PackInspector to confirm the results or further inspect the executable.

For example:

- Run the Python tool to gather details like entropy, YARA matches, and ASLR status.

- Run PackInspector to see detailed information about the packer used, and compare both results.

### Using PackInspector to Verify ASLR and Other Details:
When you run PackInspector on an executable, it will generally give you insights into:

- Whether ASLR (Address Space Layout Randomization) is disabled.

- Which packer was used (e.g., UPX).

- The import table of the executable.

- The entropy of sections (indicating whether it’s packed).

If ASLR is disabled, you will be able to see that in the PackInspector output. You can then follow the steps from your exam to:

- Disable ASLR (if needed) and take a screenshot.

- Extract strings from memory to see unpacked content.

- Use Scylla to dump and rebuild the import table.

### ⚠️ Disclaimer

- This tool is intended for **educational** and **testing** purposes only.
- Use it only on files that you are authorized to analyze.  
- Unauthorized analysis, distribution, or reverse engineering of third-party software may violate software licenses and/or laws.
- This packing.exe file should not be run on any device unless it is executed within a separate, isolated virtual machine (VM). Running it on your main system may expose your device to potential risks.
- The author and Utah Valley University are **not responsible** for any misuse of this tool. Always ensure you are in compliance with applicable local, state, federal, and international laws.

