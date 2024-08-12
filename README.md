
README.md
# HackerHunter

Welcome to HackerHunter! This repository showcases my skills in identifying, analyzing, and prosecuting hackers. Here you'll find scripts and tools that I use to catch cybercriminals.

## Features
- **Directory Scanner**: Scans directories for suspicious files.
- **Log Analyzer**: Analyzes logs for patterns indicative of hacking attempts.
- **Report Generator**: Generates detailed reports of findings.

## Usage
1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/HackerHunter.git
    ```
2. Navigate to the `scripts` directory:
    ```bash
    cd HackerHunter/scripts
    ```
3. Run the scripts as needed:
    ```bash
    python scan_directory.py
    python analyze_logs.py
    python report_generator.py
    ```

## Disclaimer
This repository is for educational purposes only. Use these tools responsibly.

scan_directory.py
Python

import os

# List of common malware file extensions
malware_extensions = ['.exe', '.dll', '.scr', '.pif', '.bat', '.cmd', '.vbs', '.js', '.jar']

def scan_directory(directory):
    suspicious_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in malware_extensions):
                suspicious_files.append(os.path.join(root, file))
    
    return suspicious_files

def print_report(suspicious_files):
    if suspicious_files:
        print("Suspicious files found:")
        for file in suspicious_files:
            print(file)
    else:
        print("No suspicious files found.")

if __name__ == "__main__":
    directory_to_scan = input("Enter the directory to scan: ")
    suspicious_files = scan_directory(directory_to_scan)
    print_report(suspicious_files)
AI-generated code. Review and use carefully. More info on FAQ.
analyze_logs.py
Python

import os

def analyze_logs(log_directory):
    suspicious_patterns = ['failed login', 'unauthorized access', 'malware detected']
    suspicious_entries = []

    for root, dirs, files in os.walk(log_directory):
        for file in files:
            with open(os.path.join(root, file), 'r') as log_file:
                for line in log_file:
                    if any(pattern in line for pattern in suspicious_patterns):
                        suspicious_entries.append(line.strip())

    return suspicious_entries

def print_analysis(suspicious_entries):
    if suspicious_entries:
        print("Suspicious log entries found:")
        for entry in suspicious_entries:
            print(entry)
    else:
        print("No suspicious log entries found.")

if __name__ == "__main__":
    log_directory = input("Enter the log directory to analyze: ")
    suspicious_entries = analyze_logs(log_directory)
    print_analysis(suspicious_entries)
AI-generated code. Review and use carefully. More info on FAQ.
report_generator.py
Python

def generate_report(suspicious_files, suspicious_entries):
    with open('report.txt', 'w') as report:
        report.write("HackerHunter Report\n")
        report.write("===================\n\n")
        
        report.write("Suspicious Files:\n")
        if suspicious_files:
            for file in suspicious_files:
                report.write(f"{file}\n")
        else:
            report.write("No suspicious files found.\n")
        
        report.write("\nSuspicious Log Entries:\n")
        if suspicious_entries:
            for entry in suspicious_entries:
                report.write(f"{entry}\n")
        else:
            report.write("No suspicious log entries found.\n")

if __name__ == "__main__":
    suspicious_files = ['example.exe', 'malware.dll']  # Example data
    suspicious_entries = ['failed login attempt from 192.168.1.1']  # Example data
    generate_report(suspicious_files, suspicious_entries)
    print("Report generated: report.txt")
