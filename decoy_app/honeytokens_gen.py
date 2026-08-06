"""
Honey Assets / Honeytokens (spec Components 10 & 11).

Generates entirely synthetic fake credentials/documents, each embedding a
unique token ID so any later sighting of that exact string (e.g. in a
paste-site scrape, or an attacker's exfil dump) can be traced back to this
one decoy instance. All values below are fake and non-functional — they do
not correspond to any real account, key, or service.
"""
import json
import os
import uuid
from pathlib import Path

HONEYTOKEN_DIR = Path(__file__).parent / "honeytokens"
CANARY_CONFIG = Path(__file__).parent.parent / "config" / "canary_tokens.json"


def _tok():
    return uuid.uuid4().hex[:12]


def generate_honeytokens():
    HONEYTOKEN_DIR.mkdir(parents=True, exist_ok=True)
    tokens = {}

    # Attempt to load the active Canary Token.
    #
    # From the environment first, because config/canary_tokens.json is no
    # longer shipped into the decoy image: a config file listing the bait
    # tells whoever reads it which of the credentials lying around in here are
    # bait, which is the one thing they must not learn. The values are passed
    # in as environment variables at deploy time instead, where a leaked cloud
    # key is an entirely ordinary thing for a server to be carrying. The file
    # is still read when running on the host directly.
    aws_key = os.environ.get("AWS_ACCESS_KEY_ID")
    aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not (aws_key and aws_secret) and CANARY_CONFIG.exists():
        try:
            data = json.loads(CANARY_CONFIG.read_text())
            aws_key = data.get("AWS_ACCESS_KEY_ID")
            aws_secret = data.get("AWS_SECRET_ACCESS_KEY")
        except Exception:
            pass


    if aws_key and aws_secret:
        tokens["aws_keys.txt"] = (
            f"# Asteria Holdings — Cloud Ops (Production)\n"
            f"AWS_ACCESS_KEY_ID={aws_key}\n"
            f"AWS_SECRET_ACCESS_KEY={aws_secret}\n"
            f"AWS_DEFAULT_REGION=us-east-1\n"
        )
    else:
        aws_id = _tok()
        tokens["aws_keys.txt"] = (
            f"# Asteria Holdings — Cloud Ops (FAKE, decoy token {aws_id})\n"
            f"AWS_ACCESS_KEY_ID=AKIA{aws_id.upper()}\n"
            f"AWS_SECRET_ACCESS_KEY=fake{aws_id}0000000000000000000000\n"
            f"AWS_DEFAULT_REGION=us-east-1\n"
        )

    ssh_id = _tok()
    tokens["id_rsa_backup.txt"] = (
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"FAKEDECOYKEY{ssh_id}NOTAREALKEYDONOTUSE\n"
        f"-----END OPENSSH PRIVATE KEY-----\n"
    )

    db_id = _tok()
    tokens["db_credentials.txt"] = (
        f"# decoy token {db_id}\n"
        f"DB_HOST=sql01.asteriaholdings.example\n"
        f"DB_USER=svc_reporting\n"
        f"DB_PASS=Fake!{db_id}Passw0rd\n"
    )

    vpn_id = _tok()
    tokens["vpn_config.ovpn"] = (
        f"# decoy token {vpn_id} — Asteria Holdings VPN (FAKE)\n"
        f"remote vpn.asteriaholdings.example 1194\n"
        f"proto udp\ndev tun\n"
    )

    inv_id = _tok()
    tokens["invoice_04178.pdf.txt"] = (
        f"ASTERIA HOLDINGS — INVOICE #04178 (decoy token {inv_id})\n"
        f"Vendor: Northbridge Supplies Ltd\nAmount: $18,420.00\nStatus: Pending approval\n"
    )

    hr_id = _tok()
    tokens["employee_records_export.csv"] = (
        f"# decoy token {hr_id}\n"
        "employee_id,name,department,salary\n"
        "E1001,Jordan Reyes,Finance,88000\n"
        "E1002,Priya Nataraj,Engineering,102000\n"
        "E1003,Sam O'Connell,HR,76000\n"
    )

    for filename, content in tokens.items():
        (HONEYTOKEN_DIR / filename).write_text(content, encoding="utf-8")

    return list(tokens.keys())


if __name__ == "__main__":
    print("Generated:", generate_honeytokens())
