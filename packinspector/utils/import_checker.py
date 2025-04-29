import pefile

def list_imports(file_path):
    pe = pefile.PE(file_path)
    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode())
    return imports
