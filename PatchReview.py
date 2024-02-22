# PatchReview
# Copyright (C) 2021 Kevin Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/msrc-api
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import requests
import re

base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/'

headers = {'Accept': 'application/json'}

vuln_types = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    'Tampering',
    'Edge - Chromium'
    ]

vuln_severity = [
    'Critical',
    'Important',
    'Moderate',
    'Low'
]


def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 0:
                if search_type == "Edge - Chromium":
                    if threat['ProductID'][0] == '11655':
                        counter += 1
                        break
                elif threat['Description'].get('Value') == search_type:
                    if threat['ProductID'][0] == '11655':
                        # Do not double count Chromium Vulns
                        break
                    counter += 1
                    break
    return counter

def count_severity(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 3:
                if search_type == "Edge - Chromium":
                    if threat['ProductID'][0] == '11655':
                        counter += 1
                        break
                elif threat['Description'].get('Value') == search_type:
                    if threat['ProductID'][0] == '11655':
                        # Do not double count Chromium Vulns
                        break
                    counter += 1
                    break
    return counter

def count_exploited(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)

        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploited:Yes' in description:
                    counter += 1
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

def count_zeroday(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)

        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if ('Publicly Disclosed:Yes' in description) or ('Exploited:Yes' in description):
                    counter += 1
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

def exploitation_likely(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploitation More Likely'.lower() in description.lower():
                    counter += 1
                    cves.append(f'{vuln["CVE"]} -- {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

"""
check the date format is yyyy-mmm
"""
def check_data_format(date_string):
    date_pattern = '\\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
    if re.match(date_pattern, date_string, re.IGNORECASE):
        return True

def print_header(title):
    print("[+] Microsoft Patch Tuesday Stats")
    print("[+] A modified version of:")
    print("[+] https://github.com/Immersive-Labs-Sec/msrc-api")
    print(f"[+] {title}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read vulnerability stats for a patch tuesday release.')
    parser.add_argument('security_update', help="Date string for the report query in format YYYY-mmm")

    args = parser.parse_args()

    if not check_data_format(args.security_update):
        print("[!] Invalid date format please use 'yyyy-mmm'")
        exit()

    # Get the list of all vulns
    get_sec_release = requests.get(f'{base_url}cvrf/{args.security_update}', headers=headers)

    if get_sec_release.status_code != 200:
        print(f"[!] Thats a {get_sec_release.status_code} from MS no release notes yet")
        exit()

    release_json = get_sec_release.json()

    title = release_json.get('DocumentTitle', 'Release not found').get('Value')

    all_vulns = release_json.get('Vulnerability', [])

    len_vuln = len(all_vulns)

    print_header(title)
        
    # Print the total number of vulnerabilities
    count_total = 0
    for vuln_type in vuln_types:
        count = count_type(vuln_type, all_vulns)
        count_total = count_total + count
    print(f'\n[+] Found a total of {count_total} vulnerabilities')

    # Print the different types of vulnerability
    for vuln_type in vuln_types:
        count = count_type(vuln_type, all_vulns)
        print(f'  [-] {count} {vuln_type} Vulnerabilities')
    
    # Print the number of vulns per severity  
    print('\n[+] Breakdown by severity')
    for vuln_severity in vuln_severity:
        count = count_severity(vuln_severity, all_vulns)
        print(f'  [-] {count} {vuln_severity} Vulnerabilities')
    
    # Count the number of zero-days
    zeroday = count_zeroday(all_vulns)
    print(f'\n[+] Found {zeroday["counter"]} zero days this month')
    print(f'[+] A zero day is defined as a vulnerability which is publicly disclosed or actively exploited with no official fix available')
    for cve in zeroday['cves']:
        print(f'  [-] {cve}')

    # Count the number of exploited vulnerabilities
    exploited = count_exploited(all_vulns)
    print(f'\n[+] Found {exploited["counter"]} exploited in the wild')
    for cve in exploited['cves']:
        print(f'  [-] {cve}')

    # Print top vulns with a CVSS score > 8
    base_score = 8.0
    print('\n[+] Highest Rated Vulnerabilities')
    for vuln in all_vulns:
        title = vuln.get('Title', {'Value': 'Not Found'}).get('Value')
        cve_id = vuln.get('CVE', '')
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_score = cvss_sets[0].get('BaseScore', 0)
            if cvss_score >= base_score:
                print(f'  [-] {cve_id} - {cvss_score} - {title}')

    # Print vulns that are marked as exploitation likely
    exploitation = exploitation_likely(all_vulns)
    print(f'\n[+] Found {exploitation["counter"]} vulnerabilites more likely to be exploited')
    for cve in exploitation['cves']:
        print(f'  [-] {cve} - https://msrc.microsoft.com/update-guide/en-US/vulnerability/{cve.split()[0]}')