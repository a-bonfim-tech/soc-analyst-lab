"""Keep the README headline numbers tied to the evidence in the repository.

The recruiter-facing headline in README.md states counts. These tests recompute
each count from the repository and fail when the headline drifts.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
INVESTIGATIONS = ROOT / "03-investigations"
EVIDENCE_README = ROOT / "10-evidence" / "README.md"
CASE_DIR = re.compile(r"^SOC-\d{4}-\d{3}$")
ESCALATED = re.compile(
    r"escalated to tier 2|decision:\s*escalate\b|tier 2 escalation (package|required)",
    re.IGNORECASE,
)
NOT_ESCALATED = re.compile(r"no tier 2 escalation required", re.IGNORECASE)


def headline_count(label):
    match = re.search(rf"(\d+) {re.escape(label)}", README)
    if not match:
        raise AssertionError(f"README headline does not state '{label}'")
    return int(match.group(1))


def case_dirs():
    return sorted(p for p in INVESTIGATIONS.iterdir() if p.is_dir() and CASE_DIR.match(p.name))


def escalated_cases():
    cases = []
    for case in case_dirs():
        decision = case / "escalation.md"
        if not decision.exists():
            continue
        text = decision.read_text(encoding="utf-8")
        if ESCALATED.search(text) and not NOT_ESCALATED.search(text):
            cases.append(case.name)
    return cases


def category_rows():
    text = EVIDENCE_README.read_text(encoding="utf-8")
    section = text.split("## Evidence and telemetry categories", 1)
    if len(section) != 2:
        raise AssertionError("10-evidence/README.md has no categories section")
    body = section[1].split("\n## ", 1)[0]
    return [line for line in body.splitlines() if re.match(r"^\|\s*\d+\s*\|", line)]


def slug(heading):
    return re.sub(r"[^a-z0-9 -]", "", heading.lower()).strip().replace(" ", "-")


class ReadmeClaimsTest(unittest.TestCase):
    def test_investigation_count_matches_case_directories(self):
        cases = case_dirs()
        for case in cases:
            self.assertTrue((case / "investigation.md").exists(), f"{case.name} has no investigation.md")
        self.assertEqual(headline_count("documented SOC investigations"), len(cases))

    def test_tier2_escalation_count_matches_escalation_decisions(self):
        cases = escalated_cases()
        self.assertEqual(headline_count("Tier 2 escalation decisions"), len(cases), cases)
        for case in cases:
            self.assertIn(f"03-investigations/{case}/escalation.md", README, f"{case} is not linked in the headline")

    def test_category_count_matches_evidence_table(self):
        rows = category_rows()
        self.assertEqual(headline_count("evidence/telemetry categories"), len(rows))
        numbers = [int(re.match(r"^\|\s*(\d+)", row).group(1)) for row in rows]
        self.assertEqual(numbers, list(range(1, len(rows) + 1)), "category rows must be numbered 1..n")

    def test_category_evidence_links_exist(self):
        for row in category_rows():
            links = re.findall(r"\]\(([^)#]+)\)", row)
            self.assertTrue(links, f"row has no evidence link: {row}")
            for link in links:
                self.assertTrue((EVIDENCE_README.parent / link).exists(), f"missing evidence: {link}")

    def test_category_cases_exist(self):
        existing = {p.name for p in case_dirs()}
        for row in category_rows():
            for case in re.findall(r"SOC-\d{4}-\d{3}", row.split("|")[3]):
                self.assertIn(case, existing)

    def test_readme_anchor_to_categories_resolves(self):
        headings = re.findall(r"^#{1,6} (.+)$", EVIDENCE_README.read_text(encoding="utf-8"), re.MULTILINE)
        anchors = {slug(h) for h in headings}
        for anchor in re.findall(r"10-evidence/README\.md#([a-z0-9-]+)", README):
            self.assertIn(anchor, anchors)


if __name__ == "__main__":
    unittest.main()
