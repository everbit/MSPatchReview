# PatchReview

A tool to analyze Microsoft's monthly security updates (Patch Tuesday) and provide a comprehensive breakdown of vulnerabilities.

## Overview

PatchReview queries Microsoft's Security Response Center (MSRC) API to retrieve and analyze security bulletins from Microsoft's monthly patch releases. It presents the information in an easily digestible format with statistics on vulnerability types, severity levels, zero-days, and more.

## Features

- Retrieve security bulletins for specific Microsoft Patch Tuesday releases
- Count and categorize vulnerabilities by type (RCE, EoP, etc.)
- Analyze severity levels of reported vulnerabilities
- Identify zero-day vulnerabilities
- Highlight exploited vulnerabilities
- List vulnerabilities with high CVSS scores
- Flag vulnerabilities more likely to be exploited in the future

## Prerequisites

- Python 3.6+
- `requests` library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/PatchReview.git
   cd PatchReview
   ```

2. Install dependencies:
   ```bash
   pip install requests
   ```

## Usage

Run the script with a date argument in the format `YYYY-MMM` (e.g., 2023-Nov):

```bash
python PatchReview.py 2023-Nov
```

This will retrieve and analyze Microsoft's security bulletin for November 2023.

### Example Output

```
[+] Microsoft Patch Tuesday Stats
[+] A modified version of:
[+] https://github.com/Immersive-Labs-Sec/msrc-api
[+] November 2023 Security Updates

[+] Found a total of 65 vulnerabilities
  [-] 18 Elevation of Privilege Vulnerabilities
  [-] 1 Security Feature Bypass Vulnerabilities
  [-] 27 Remote Code Execution Vulnerabilities
  [-] 10 Information Disclosure Vulnerabilities
  [-] 3 Denial of Service Vulnerabilities
  [-] 4 Spoofing Vulnerabilities
  [-] 2 Tampering Vulnerabilities
  [-] 0 Edge - Chromium Vulnerabilities

[+] Breakdown by severity
  [-] 8 Critical Vulnerabilities
  [-] 55 Important Vulnerabilities
  [-] 2 Moderate Vulnerabilities
  [-] 0 Low Vulnerabilities

[+] Found 1 zero days this month
[+] A zero day is defined as a vulnerability which is publicly disclosed or actively exploited with no official fix available
  [-] CVE-2023-35628 - 7.8 - Windows Overlay Filter Elevation of Privilege Vulnerability

[+] Found 1 exploited in the wild
  [-] CVE-2023-35628 - 7.8 - Windows Overlay Filter Elevation of Privilege Vulnerability

[+] Highest Rated Vulnerabilities
  [-] CVE-2023-35641 - 8.8 - Windows Hyper-V Remote Code Execution Vulnerability
  [-] CVE-2023-36036 - 8.8 - Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability
  [-] CVE-2023-35631 - 8.8 - Microsoft Message Queuing Remote Code Execution Vulnerability

[+] Found 3 vulnerabilites more likely to be exploited
  [-] CVE-2023-35628 -- Windows Overlay Filter Elevation of Privilege Vulnerability - https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-35628
  [-] CVE-2023-36033 -- Windows Mark of the Web Security Feature Bypass Vulnerability - https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-36033
  [-] CVE-2023-36052 -- Windows Pragmatic General Multicast (PGM) Remote Code Execution Vulnerability - https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-36052
```

## Understanding the Results

The script provides the following information:

- **Total Count**: Total number of vulnerabilities addressed in the update
- **Vulnerability Types**: Breakdown by vulnerability category (RCE, EoP, etc.)
- **Severity Breakdown**: Count of vulnerabilities by severity level
- **Zero Days**: Vulnerabilities that were publicly disclosed or exploited before patches were available
- **Exploited in the Wild**: Vulnerabilities actively being exploited
- **Highest Rated**: Vulnerabilities with CVSS scores of 8.0 or higher
- **Likely to be Exploited**: Vulnerabilities Microsoft has flagged as more likely to see exploitation

## Vulnerability Categories

- **Remote Code Execution (RCE)**: Allows attackers to execute arbitrary code
- **Elevation of Privilege (EoP)**: Enables attackers to gain higher privileges
- **Information Disclosure**: Leaks sensitive information
- **Security Feature Bypass**: Circumvents security features
- **Denial of Service (DoS)**: Renders services unavailable
- **Spoofing**: Masquerades as another entity
- **Tampering**: Allows modification of data or code
- **Edge - Chromium**: Vulnerabilities specific to Microsoft Edge browser

## Limitations

- The script only analyzes one month's security updates at a time
- Relies on the Microsoft Security Update API which may change over time
- Does not provide detailed information about individual patches or fixes

## Credits

This script is a modified version of the tool created by Immersive Labs:
https://github.com/Immersive-Labs-Sec/msrc-api

## License

Released under the MIT License.

Copyright (C) 2021 Kevin Breen, Immersive Labs
