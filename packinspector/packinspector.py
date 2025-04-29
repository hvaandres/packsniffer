import argparse
from utils.aslr_checker import check_aslr
from utils.hasher import calculate_sha1
from utils.string_extractor import extract_strings
from utils.import_checker import list_imports

def main():
    parser = argparse.ArgumentParser(description="PackInspector - Static PE Analysis Tool")
    parser.add_argument("filepath", help="Path to the PE file to analyze")
    args = parser.parse_args()

    filepath = args.filepath

    print(f"[+] Analyzing file: {filepath}")

    # Check ASLR
    aslr_enabled = check_aslr(filepath)
    print(f"[+] ASLR Enabled: {aslr_enabled}")

    if aslr_enabled:
        print("[!] You need to disable ASLR using CFF Explorer manually!")

    # Calculate SHA-1
    sha1_hash = calculate_sha1(filepath)
    print(f"[+] SHA-1: {sha1_hash}")

    # Extract Strings
    strings = extract_strings(filepath)
    print(f"[+] Found {len(strings)} printable strings.")
    for s in strings[:10]:  # print only first 10
        print(f"    {s}")

    # List Imports
    imports = list_imports(filepath)
    print(f"[+] Imports Detected ({len(imports)}):")
    for imp in imports:
        print(f"    {imp}")

if __name__ == "__main__":
    main()
