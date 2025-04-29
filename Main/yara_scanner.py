import yara

def scan_with_yara(filepath, rule_path="packer_rules.yar"):
    try:
        rules = yara.compile(filepath=rule_path)
        matches = rules.match(filepath)
        return [match.rule for match in matches]
    except Exception as e:
        return [f"YARA error: {e}"]
