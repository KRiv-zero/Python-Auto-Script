import re
import requests
import hashlib

# === Sample Email Body (Simulated Phishing Email) ===
email_body = '''
Subject: Urgent Payment Needed

Hi,

Please see the attached invoice and click the following link to confirm payment.

http://malicious-login.fake/invoice

Thanks,
Finance Department
'''

# === Step 1: Extract URLs from Email ===
urls = re.findall(r'(https?://[\w\.-]+)', email_body)
print("[+] Extracted URLs:")
for url in urls:
    print("   ", url)

# === Step 2: Hash the Attachment (Simulated) ===
attachment_name = "invoice.pdf"
attachment_content = b"This is a fake malicious attachment pretending to be a PDF"
hash_object = hashlib.sha256(attachment_content)
attachment_hash = hash_object.hexdigest()
print(f"\n[+] SHA-256 Hash of attachment '{attachment_name}': {attachment_hash}")

# === Step 3: VirusTotal URL Reputation Check ===
# Requires a VirusTotal API key. Replace "YOUR_API_KEY" below.
api_key = "YOUR_API_KEY"
headers = {
    "x-apikey": api_key
}

def check_url_virustotal(url):
    # Submit the URL
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(submit_url, headers=headers, data={"url": url})
    
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        # Get the report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        report_response = requests.get(report_url, headers=headers)

        if report_response.status_code == 200:
            stats = report_response.json()["data"]["attributes"]["stats"]
            print(f"\n[+] VirusTotal Report for {url}:")
            print(f"    Malicious: {stats['malicious']}")
            print(f"    Suspicious: {stats['suspicious']}")
            print(f"    Harmless: {stats['harmless']}")
        else:
            print("    [-] Failed to fetch analysis report.")
    else:
        print("    [-] Failed to submit URL to VirusTotal.")

# === Step 4: Run URL Reputation Check for Each Extracted URL ===
for url in urls:
    check_url_virustotal(url)

# === Final Output Summary ===
print("\n[✓] Phishing triage complete. Extracted IOCs and checked URL reputation.")

