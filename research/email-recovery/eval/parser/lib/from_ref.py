"""Reference RFC 5322 reading of From field values, one JSON object per line.

Python's standard-library header parser (``email.headerregistry`` over
``email._header_value_parser``) implements the RFC 5322 grammar, obsolete
syntax included, and records a defect for each departure from it. Each
input line is ``{"id": ..., "value": <the field value, latin-1>}``; each
output line is ``{"id", "python", "mailboxes": [{"addr_spec", "local",
"domain", "display_name"}], "groups", "defects"}``.
"""

import json
import sys
from email.headerregistry import HeaderRegistry

registry = HeaderRegistry()


def read(value):
    out = {"mailboxes": [], "groups": 0, "defects": []}
    try:
        header = registry("From", value)
    except Exception as err:  # the parser raises only on input it cannot represent
        out["defects"].append(f"{type(err).__name__}: {err}")
        return out
    out["defects"] = [f"{type(d).__name__}: {d}" for d in header.defects]
    out["groups"] = sum(1 for g in header.groups if g.display_name is not None)
    for a in header.addresses:
        out["mailboxes"].append({
            "addr_spec": a.addr_spec,
            "local": a.username,
            "domain": a.domain,
            "display_name": a.display_name,
        })
    return out


def main():
    version = sys.version.split()[0]
    for line in sys.stdin:
        req = json.loads(line)
        res = read(req["value"])
        res["id"] = req["id"]
        res["python"] = version
        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
