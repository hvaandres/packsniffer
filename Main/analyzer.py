# This script analyzes a PE file for packing and obfuscation techniques.
# It checks for UPX signatures, analyzes section entropy, and scans for YARA rules.
# It also checks for control flow obfuscation and imports.
# Disclaimer: This script is for educational purposes only. Use it responsibly and ethically.
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import argparse
import pefile
from Main.pe_analysis import analyze_sections, check_imports, check_upx_signature
from yara_scanner import scan_with_yara
from obfuscation_detector import detect_control_flow_obfuscation

def analyze_file(filepath):
    try:
        pe = pefile.PE(filepath)
    except Exception as e:
        return {"error": f"Failed to parse PE file: {e}"}

    entropy_results = analyze_sections(pe)
    import_count = check_imports(pe)
    yara_matches = scan_with_yara(filepath)
    upx_detected = check_upx_signature(pe)
    obfuscation_analysis = detect_control_flow_obfuscation(pe)

    is_packed = upx_detected or any(s["suspicious_entropy"] or s["suspicious_size"] for s in entropy_results)
    is_obfuscated = import_count == 0 or "Jump instructions found" in obfuscation_analysis

    return {
        "file": filepath,
        "is_packed": is_packed,
        "is_obfuscated": is_obfuscated,
        "entropy_results": entropy_results,
        "import_count": import_count,
        "yara_matches": yara_matches,
        "upx_detected": upx_detected,
        "obfuscation_analysis": obfuscation_analysis
    }

def main():
    parser = argparse.ArgumentParser(description="Analyze PE file for packing and obfuscation")
    parser.add_argument("file", help="Path to the PE file")
    args = parser.parse_args()

    result = analyze_file(args.file)

    if "error" in result:
        print(result["error"])
    else:
        print(f"\nFile: {result['file']}")
        print(f"Packed: {'Yes' if result['is_packed'] else 'No'}")
        print(f"Obfuscated: {'Yes' if result['is_obfuscated'] else 'No'}")
        print(f"YARA Matches: {', '.join(result['yara_matches']) if result['yara_matches'] else 'None'}")
        print(f"UPX Detected: {'Yes' if result['upx_detected'] else 'No'}")
        print(f"Import Count: {result['import_count']}")
        print(f"Obfuscation Analysis: {result['obfuscation_analysis']}")
        print("\nSection Entropy Analysis:")
        for section in result["entropy_results"]:
            print(f" - {section['section_name']}: Entropy={section['entropy']:.2f}, Suspicious={section['suspicious_entropy'] or section['suspicious_size']}")

if __name__ == "__main__":
    main()
