# Log-Analyzer
A simple Python tool to detect suspicious login activity by analyzing server logs and tracking failed login attempts per IP address. 🔐
# Failed Login Detector 🔐

A simple Python-based cybersecurity project that analyzes server log files and identifies suspicious login activity by tracking failed login attempts from different IP addresses.

I built this project to improve my Python skills and understand how basic log analysis works in cybersecurity.

## 📌 About the Project

When someone tries to log in to a system multiple times with the wrong credentials, it can sometimes indicate a possible brute-force attack.

This tool reads a server log file, counts failed login attempts for each IP address, and raises an alert if an IP crosses a specified threshold.

It also displays a report sorted by the highest number of failed login attempts.

## ✨ Features

- Reads server logs from a file.
- Counts failed login attempts for each IP address.
- Flags IP addresses that cross a defined threshold.
- Displays a clean and easy-to-read report.
- Sorts results from the highest number of failed attempts to the lowest.

## 🛠️ Built With

- Python 3

## ⚙️ How It Works

1. The program reads a server log file.
2. It identifies failed login attempts.
3. It counts the failed attempts associated with each IP address.
4. It compares the counts against a predefined threshold.
5. It displays an alert for IP addresses that cross the threshold.
6. Finally, it prints a report sorted by the number of failed attempts.

## 🚀 How to Run

**1. Clone the repository**

```bash
git clone https://github.com/YOUR-USERNAME/failed-login-detector.git
```

**2. Open the project folder**

```bash
cd failed-login-detector
```

**3. Run the Python script**

Replace `main.py` with your actual Python filename if it is different.

```bash
python main.py
```

Make sure your log file is in the location expected by the script.

## 📊 Sample Output

The output may look something like this:

```text
===== Failed Login Report =====

IP Address       Failed Attempts      Status
192.168.1.10     12                    ALERT
192.168.1.25     8                     ALERT
192.168.1.30     3                     Normal
192.168.1.45     1                     Normal

================================
```

*Note: This is an example of the expected output format. The actual output depends on your code, log file, and alert threshold.*

## 🎯 What I Learned

While working on this project, I got practical experience with Python, file handling, log analysis, dictionaries, and sorting data.

I also learned how repeated failed login attempts can be useful when investigating potentially suspicious activity.

## 🔮 Future Improvements

I would like to improve this project by adding:

- Live log monitoring.
- A simple dashboard to display suspicious login activity.
- More detailed alerts and reporting.
- Better handling of different log formats.

## ⚠️ Disclaimer

This project is created for educational purposes to practice Python programming and basic cybersecurity concepts. It is a simple log analysis tool and should not be considered a complete intrusion detection system.

## 👨‍💻 Author

Created by **YOUR NAME**

I'm currently learning about Cloud Computing, Cybersecurity, and Python, and this project is part of my learning journey.
