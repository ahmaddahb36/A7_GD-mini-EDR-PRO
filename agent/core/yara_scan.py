
import os
import yara

_rules = None

def _load_rules():
    global _rules
    if _rules is None:
        rules_path = os.path.join(os.path.dirname(__file__), "..", "rules", "rules.yar")
        _rules = yara.compile(filepath=os.path.abspath(rules_path))
    return _rules

def scan():
    try:
        rules = _load_rules()
        return [str(m) for m in rules.match()]
    except:
        return []

def scan_file(path):
    try:
        rules = _load_rules()
        return [str(m) for m in rules.match(filepath=path)]
    except:
        return []
