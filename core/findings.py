from core.finding import Finding

class FindingsManager:
    def __init__(self):
        self.findings = []

    def add(self, finding: Finding):
        self.findings.append(finding)

    def summary(self):
        summary = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        for f in self.findings:
            summary[f.severity] += 1
        return summary

    def to_dict(self):
        return [f.to_dict() for f in self.findings]

    def to_html_rows(self):
        return "".join(f.to_html() for f in self.findings)

