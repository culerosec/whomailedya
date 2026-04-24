#!/usr/bin/env python3

import dns.resolver
import argparse
import json
import re


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


# ------------------------
# DOMAIN SPOOF CHECKER
# ------------------------
class DomainSpoofChecker:
    def __init__(self, domain):
        self.domain = domain.lower().strip()
        self.visited_spf = set()
        self.lookup_count = 0
        self.external_includes = set()
        self.max_depth = 10

    # ---------------- DNS ----------------
    def get_txt_records(self, name):
        try:
            return [r.to_text().strip('"') for r in dns.resolver.resolve(name, "TXT")]
        except Exception:
            return []

    def has_mx(self):
        try:
            dns.resolver.resolve(self.domain, "MX")
            return True
        except Exception:
            return False

    def has_dnssec(self):
        try:
            dns.resolver.resolve(self.domain, "DNSKEY")
            return True
        except Exception:
            return False

    # ---------------- ATTACK SIMULATION ENGINE ----------------
    def simulate_attack_paths(self, spf, dmarc, dkim):
        paths = []

        spf_record = spf["record"]
        dmarc_policy = dmarc["policy"]

        # 1. SPF include abuse
        if spf_record and "include:" in spf_record:
            paths.append({
                "vector": "SPF third-party relay abuse",
                "steps": [
                    "Identify allowed SPF include provider",
                    "Use legitimate SaaS sender account",
                    "Send email through trusted infrastructure",
                    "Pass SPF via include chain"
                ],
                "success_probability": "high"
            })

        # 2. DMARC none bypass
        if dmarc_policy == "none":
            paths.append({
                "vector": "DMARC enforcement bypass",
                "steps": [
                    "Forge From header",
                    "Send via any SMTP server",
                    "No enforcement policy exists",
                    "Email accepted by recipient"
                ],
                "success_probability": "very high"
            })

        # 3. DKIM missing
        if not dkim["exists"]:
            paths.append({
                "vector": "Header spoofing (no DKIM)",
                "steps": [
                    "Forge email headers",
                    "Send via arbitrary SMTP relay",
                    "No cryptographic validation",
                    "Email appears legitimate"
                ],
                "success_probability": "high"
            })

        # 4. relaxed alignment
        if dmarc.get("aspf") == "r" or dmarc.get("adkim") == "r":
            paths.append({
                "vector": "Relaxed alignment exploitation",
                "steps": [
                    "Use subdomain or similar domain",
                    "Pass relaxed SPF/DKIM checks",
                    "Exploit human trust in display domain"
                ],
                "success_probability": "medium"
            })

        # 5. full spoof
        if not spf_record and dmarc_policy in [None, "none"]:
            paths.append({
                "vector": "Full domain impersonation",
                "steps": [
                    "Set From header to target domain",
                    "Send from any SMTP server",
                    "No authentication enforcement",
                    "Full spoof succeeds"
                ],
                "success_probability": "very high"
            })

        return paths

    # ---------------- SPF ----------------
    def get_spf_record(self, domain):
        for r in self.get_txt_records(domain):
            if r.startswith("v=spf1"):
                return r
        return None

    def parse_spf(self, domain, depth=0):
        if domain in self.visited_spf or depth > self.max_depth:
            return

        self.visited_spf.add(domain)

        spf = self.get_spf_record(domain)
        if not spf:
            return

        for mech in spf.split()[1:]:
            if mech.startswith("include:"):
                included = mech.split("include:")[1]
                self.lookup_count += 1
                self.parse_spf(included, depth + 1)

            elif mech.startswith("redirect="):
                self.lookup_count += 1
                self.parse_spf(mech.split("redirect=")[1], depth + 1)

            elif mech.startswith(("a", "mx", "exists")):
                self.lookup_count += 1

    def analyze_spf(self):
        self.lookup_count = 0
        self.visited_spf = set()

        spf = self.get_spf_record(self.domain)

        result = {
            "record": spf,
            "lookup_count": 0,
            "too_many_lookups": False
        }

        if not spf:
            return result

        self.parse_spf(self.domain)

        result["lookup_count"] = self.lookup_count
        result["too_many_lookups"] = self.lookup_count > 10

        return result

    # ---------------- DMARC ----------------
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
            "subdomain_policy": None,
        }

        if not record:
            return result

        tags = {}
        for part in record.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip()] = v.strip()

        result["policy"] = tags.get("p", "none")
        result["aspf"] = tags.get("aspf", "r")
        result["adkim"] = tags.get("adkim", "r")
        result["subdomain_policy"] = tags.get("sp")

        return result

    # ---------------- DKIM ----------------
    def has_dkim(self):
        selectors = ["default", "google", "selector1", "selector2"]

        for sel in selectors:
            try:
                dns.resolver.resolve(f"{sel}._domainkey.{self.domain}", "TXT")
                return {"exists": True}
            except:
                continue

        return {"exists": False}

    # ---------------- SCORE ----------------
    def score(self, spf, dmarc, dkim, mx):
        score = 100

        if not dmarc["record"]:
            score -= 40
        elif dmarc["policy"] == "none":
            score -= 30

        if not spf["record"]:
            score -= 20

        if not dkim["exists"]:
            score -= 20

        if not mx:
            score -= 10

        return max(score, 0)

    # ---------------- RUN ----------------
    def run(self):
        spf = self.analyze_spf()
        dmarc = self.parse_dmarc()
        dkim = self.has_dkim()
        mx = self.has_mx()

        score = self.score(spf, dmarc, dkim, mx)
        issues = []

        attack_sim = self.simulate_attack_paths(spf, dmarc, dkim)

        result = {
            "domain": self.domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "mx": mx,
            "dnssec": self.has_dnssec(),
            "score": score,
            "issues": issues,
            "attack_simulation": attack_sim
        }

        # ---------------- CLI OUTPUT (YOUR ORIGINAL STYLE RESTORED) ----------------
        print(f"\n{bold('DOMAIN:')} {self.domain}")

        print(f"\n{bold('SPF:')}")
        print("Record:", spf["record"])
        print("Lookups:", spf["lookup_count"])

        print(f"\n{bold('DMARC:')}")
        print("Record:", dmarc["record"])
        print("Policy:", dmarc["policy"])
        print("Subdomain Policy:", dmarc["subdomain_policy"])
        print("aspf:", dmarc["aspf"])
        print("adkim:", dmarc["adkim"])

        print(f"\n{bold('DKIM:')} {dkim}")
        print(f"{bold('MX:')} {mx}")
        print(f"{bold('DNSSEC:')} {result['dnssec']}")

        print(f"\n{bold('SCORE:')} {score}")

        if score < 70:
            print(c("SPOOFABLE / HIGH RISK", Style.RED))
        else:
            print(c("LOWER RISK", Style.GREEN))

        print(f"\n{bold('ISSUES:')}")
        for issue in issues:
            print(f"- {issue}")

        return result


# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(description="Domain spoofing analyzer")
    parser.add_argument("domain")
    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    checker = DomainSpoofChecker(args.domain)
    result = checker.run()

    if args.json:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
