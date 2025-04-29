import hashlib

def calculate_sha1(file_path):
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha1.update(chunk)
    return sha1.hexdigest()
