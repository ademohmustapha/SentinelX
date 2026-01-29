🛡️ Kryphorix Security Scanner

Kryphorix is a modular security assessment toolkit built for scanning and identifying common security weaknesses across networks, web applications, APIs, TLS configurations, Active Directory environments, and wireless networks.

It is designed for security auditing, learning, and defensive testing.

🚀 Features

🌐 Web security scanning

🔌 API misconfiguration detection

🖥️ Port scanning

🔐 TLS/SSL certificate & protocol checks

🏢 Active Directory exposure checks

📡 Wireless network security scan

📊 Automatic JSON & PDF report generation

🧩 Modular architecture

📸 Screenshots




🛠 Installation
git clone https://github.com/YOUR_GITHUB_USERNAME/Kryphorix.git
cd Kryphorix

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

▶️ Usage

Run the tool using:

./Kryphorix.sh


Or directly:

python3 main.py


Follow the on-screen menu to choose scan types.

📁 Project Structure
Kryphorix/
│
├── core/              # Core engine (findings, UI, reports)
├── scans/             # All scanning modules
│   ├── web.py
│   ├── api.py
│   ├── port.py
│   ├── tls.py
│   ├── ad.py
│   └── wireless.py
│
├── reports/           # Generated scan reports
├── screenshots/       # Project screenshots
├── main.py
├── Kryphorix.sh
└── requirements.txt

📄 Reports

After every scan, Kryphorix automatically generates:

📑 PDF Report

📊 JSON Report

Saved inside the reports/ folder.

⚠️ Disclaimer

This tool is for educational and authorized security testing only.
Do not use it on systems you do not own or have permission to test.

👨‍💻 Author

Ademoh Mustapha Onimisi

⭐ Support

If you like this project, give it a ⭐ on GitHub!
