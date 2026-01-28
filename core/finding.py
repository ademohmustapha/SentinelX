SEVERITY_SCORE = {"Info":1,"Low":3,"Medium":6,"High":9,"Critical":10}

class Finding:
    def __init__(self, title, severity, desc, fix, ref=None):
        self.title = title
        self.severity = severity
        self.desc = desc
        self.fix = fix
        self.ref = ref
        self.score = SEVERITY_SCORE.get(severity, 1)

    def to_dict(self):
        return vars(self)

    def to_html(self):
        color = {
            "Info": "blue",
            "Low": "green",
            "Medium": "orange",
            "High": "red",
            "Critical": "darkred"
        }[self.severity]

        return f"<tr><td>{self.title}</td><td style='color:{color}'>{self.severity}</td><td>{self.desc}</td><td>{self.fix}</td></tr>"

    def __str__(self):
        return f"[{self.severity}] {self.title}\n Issue: {self.desc}\n Fix: {self.fix}\n"

