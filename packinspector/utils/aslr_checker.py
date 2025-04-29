import pefile

def check_aslr(file_path):
    pe = pefile.PE(file_path)
    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    return (dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0
