import re
import requests
from urllib.parse import urlparse

# List of suspicious keywords often used in phishing URLs
phishing_keywords = ['login', 'signin', 'update', 'verify', 'secure', 'account', 'banking', 'ebayisapi', 'webscr']

# A basic list of common TLDs (Top Level Domains)
safe_tlds = ['.com', '.org', '.net', '.edu', '.gov']

# Check if the domain uses too many subdomains
def check_subdomains(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    subdomains = domain.split('.')
    # If there are more than 3 components (e.g., www.login.example.com)
    if len(subdomains) > 3:
        return True
    return False

# Check for the presence of phishing keywords in the URL
def check_phishing_keywords(url):
    for keyword in phishing_keywords:
        if keyword in url.lower():
            return True
    return False

# Check if the TLD (Top Level Domain) is suspicious
def check_tld(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    for tld in safe_tlds:
        if domain.endswith(tld):
            return False
    return True

# Check if the URL length is too long
def check_url_length(url):
    if len(url) > 75:
        return True
    return False

# Use a basic URL reputation check with a service like VirusTotal (example, optional)
# You would need to register and get an API key from VirusTotal or other services
def check_url_reputation(url):
    api_key = "YOUR_API_KEY"  # Replace with your actual VirusTotal API key
    vt_url = f"https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={url}"

    try:
        response = requests.get(vt_url)
        result = response.json()

        # If the scan results indicate a threat, return True
        if result['response_code'] == 1 and result['positives'] > 0:
            return True
    except Exception as e:
        print(f"Error checking URL reputation: {e}")
        return False

    return False

# Main phishing detection function
def phishing_link_scanner(url):
    print(f"\nScanning URL: {url}")

    # Check various factors
    if check_subdomains(url):
        print("Warning: Too many subdomains, suspicious.")
   
    if check_phishing_keywords(url):
        print("Warning: Phishing keywords detected in the URL.")
   
    if check_tld(url):
        print("Warning: Uncommon TLD (Top Level Domain) detected.")
   
    if check_url_length(url):
        print("Warning: The URL is excessively long, may be a phishing attempt.")
   
    if check_url_reputation(url):
        print("Warning: URL flagged by reputation service as malicious.")
   
    print("Scan complete.")

# Example usage
if __name__ == "__main__":
    # Replace with URLs to test
    test_urls = [
        "http://secure-login.ebayisapi.com/account/verify.php",
        "https://example.com",
        "http://https://testphp.vulnweb.com/"
    ]
   
    for url in test_urls:
        phishing_link_scanner(url)