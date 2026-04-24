#!/usr/bin/env python3

import dns.resolver
import argparse
import sys
import json


# ------------------------
# STYLE
# ------------------------
class Style:
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"


def c(text, color):
    return f"{color}{text}{Style.RESET}"


def bold(text):
    return f"{Style.BOLD}{text}{Style.RESET}"


#Domain Spoof Checker Class
class DomainSpoofChecker:
    def __init__(self, domain):
        self.domain = domain
        self.visited_spf = set()
        self.lookup_count = 0


    # DNS
    def get_txt_records(self, name):
        try:
            return [
                r.to_text().strip('"')
                for r in dns.resolver.resolve(name, "TXT")
            ]
        except Exception:
            return []

    #SPF
    def get_spf_record(self, domain):
        for r in self.get_txt_records(domain):
            if r.startswith("v=spf1"):
                return r
        return None

    def parse_spf(self, domain):
        if domain in self.visited_spf:
            return

        self.visited_spf.add(domain)

        spf = self.get_spf_record(domain)
        if not spf:
            return

        for mech in spf.split()[1:]:
            if mech.startswith("include:"):
                self.lookup_count += 1
                self.parse_spf(mech.split("include:")[1])

            elif mech.startswith("redirect="):
                self.lookup_count += 1
                self.parse_spf(mech.split("redirect=")[1])

            elif mech.startswith(("a", "mx", "exists")):
                self.lookup_count += 1

    def analyze_spf(self):
        self.lookup_count = 0
        self.visited_spf = set()

        spf = self.get_spf_record(self.domain)

        result = {
            "record": spf,
            "lookup_count": 0,
            "too_many_lookups": False,
        }

        if not spf:
            return result

        self.parse_spf(self.domain)
        result["lookup_count"] = self.lookup_count
        result["too_many_lookups"] = self.lookup_count > 10

        return result

    # DMARC
    def get_dmarc_record(self):
        for r in self.get_txt_records(f"_dmarc.{self.domain}"):
            if r.startswith("v=DMARC1"):
                return r
        return None

    def parse_dmarc(self):
        record = self.get_dmarc_record()

        result = {
            "record": record,
            "policy": None,
            "aspf": "r",
            "adkim": "r",
        }

        if not record:
            return result

        tags = {}
        for part in record.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                tags[k.strip()] = v.strip()

        result["policy"] = tags.get("p", "none")
        result["aspf"] = tags.get("aspf", "r")
        result["adkim"] = tags.get("adkim", "r")

        return result

    # SCORE
    def score(self, spf, dmarc):
        score = 100

        if not dmarc["record"]:
            score -= 40
        elif dmarc["policy"] == "none":
            score -= 30
        elif dmarc["policy"] == "quarantine":
            score -= 10

        if not spf["record"]:
            score -= 20

        if spf["too_many_lookups"]:
            score -= 30

        if dmarc["aspf"] == "r":
            score -= 5
        if dmarc["adkim"] == "r":
            score -= 5

        return max(score, 0)

    # JSON
    def collect(self):
        spf = self.analyze_spf()
        dmarc = self.parse_dmarc()
        score = self.score(spf, dmarc)

        return {
            "domain": self.domain,
            "spf": spf,
            "dmarc": dmarc,
            "score": score,
            "spoofable": score < 70
        }

    # REPORT
    def run(self):
        spf = self.analyze_spf()
        dmarc = self.parse_dmarc()
        score = self.score(spf, dmarc)

        print(f"\n{bold('DOMAIN:')} {self.domain}")

        print(f"\n{bold('SPF:')}")
        print("Record:", spf["record"])
        print("Lookups:", spf["lookup_count"])
        if spf["too_many_lookups"]:
            print(c("⚠ Too many DNS lookups (>10)", Style.RED))

        print(f"\n{bold('DMARC:')}")
        print("Record:", dmarc["record"])
        print("Policy:", dmarc["policy"])
        print("aspf:", dmarc["aspf"])
        print("adkim:", dmarc["adkim"])

        print(f"\n{bold('SCORE:')} {score}")

        if score < 70:
            print(c(bold("SPOOFABLE / HIGH RISK"), Style.RED))
        else:
            print(c(bold("LOWER RISK"), Style.GREEN))


# Main
def main():
    parser = argparse.ArgumentParser(
        description="Check a domain for email spoofing risk (SPF + DMARC analysis)."
    )

    parser.add_argument(
        "domain",
        help="Domain to analyze (e.g. example.com)"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of formatted CLI view"
    )

    args = parser.parse_args()

    checker = DomainSpoofChecker(args.domain)

    # JSON output for inegration
    if args.json:
        result = checker.collect()
        print(json.dumps(result, indent=2))
        return

    # One time report
    checker.run()


if __name__ == "__main__":
    main()
