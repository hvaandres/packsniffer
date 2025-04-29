from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

def detect_control_flow_obfuscation(pe):
    try:
        code_section = next((s for s in pe.sections if b'.text' in s.Name), None)
        if not code_section:
            return "No .text section found"

        code = code_section.get_data()
        address = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
        mode = CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)

        jmp_count = sum(1 for i in md.disasm(code, address) if i.mnemonic.startswith('jmp'))
        return f"Jump instructions found: {jmp_count} (Possible obfuscation)" if jmp_count > 100 else "No significant obfuscation detected"
    except Exception as e:
        return f"Disassembly error: {e}"
