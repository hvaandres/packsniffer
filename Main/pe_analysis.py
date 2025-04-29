# This script analyzes a PE file for packing and obfuscation techniques.

import math

def calculate_entropy(data):
    if not data:
        return 0.0
    occurences = [0] * 256
    for x in data:
        occurences[x] += 1
    entropy = 0
    for x in occurences:
        if x:
            p_x = x / len(data)
            entropy -= p_x * math.log2(p_x)
    return entropy

def analyze_sections(pe):
    results = []
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        entropy = calculate_entropy(section.get_data())
        suspicious_entropy = entropy > 7.0
        suspicious_size = section.SizeOfRawData == 0 or section.Misc_VirtualSize > 1000000
        results.append({
            "section_name": name,
            "entropy": entropy,
            "suspicious_entropy": suspicious_entropy,
            "suspicious_size": suspicious_size
        })
    return results

def check_imports(pe):
    try:
        return len(pe.DIRECTORY_ENTRY_IMPORT)
    except AttributeError:
        return 0

def check_upx_signature(pe):
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        if "UPX" in name:
            return True
    return False
