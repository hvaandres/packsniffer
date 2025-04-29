import re

def extract_strings(file_path, min_length=4):
    with open(file_path, "rb") as f:
        data = f.read()
    result = re.findall(rb"[ -~]{%d,}" % min_length, data)
    return [s.decode("ascii", errors="ignore") for s in result]
