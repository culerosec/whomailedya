# 🧠 whomailedya

> Check a domain for misconfigurations that could enable email spoofing attacks

A lightweight CLI tool that analyzes SPF + DMARC records and estimates spoofing risk.

---

## ⚙️ Usage

```bash
python spoofcheck.py [-h] [--json] domain
python spoofcheck.py google.com

If no domain is provided:

usage: spoofcheck.py [-h] [--json] domain
spoofcheck.py: error: the following arguments are required: domain

└─$ python spoofcheck.py google.com

DOMAIN: google.com

SPF:
Record: None
Lookups: 0

DMARC:
Record: v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
Policy: reject
aspf: r
adkim: r

SCORE: 70
LOWER RISK

{
  "domain": "google.com",
  "spf": {
    "record": null,
    "lookup_count": 0,
    "too_many_lookups": false
  },
  "dmarc": {
    "record": "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com",
    "policy": "reject",
    "aspf": "r",
    "adkim": "r"
  },
  "score": 70,
  "spoofable": false
}
