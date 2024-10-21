#1 Using the IP Address

import re
import requests
import socket
from urllib.parse import urlparse
import joblib
import pandas as pd


def get_domain(url):
    return urlparse(url).netloc

def is_ip_address(url):
    domain = get_domain(url)
    try:
        socket.inet_aton(domain) #Convert ip address to bytes
        return -1
    except socket.error:
        pass

    hex_ip_pattern = re.compile(r"^([0-9A-Fa-f]{2})\.([0-9A-Fa-f]{2})\.([0-9A-Fa-f]{2})\.([0-9A-Fa-f]{2})$")
    match = hex_ip_pattern.fullmatch(domain)
    if match:
        return -1

    return 1


#2 Long URL to Hide the Suspicious Part

def url_len(url):
    url_length = len(url)
    if(url_length < 54):
        return 1
    elif(54 <= url_length <=75):
        return 0
    return -1


#3 URL's having @ symbol

def is_at_symbol(url):
    if "@" in url:
        return 0
    return 1


#4 Adding prefix or suffix separated by (-) to the domain

def prefix_suffix(url):
    domain = get_domain(url)
    if "-" in domain:
        return -1
    else:
        return 1

#5 Sub Domain and Multi Sub Domains

def classify_url_by_subdomains(url):
    domain = get_domain(url)

    if domain.startswith('www.'):
        domain = domain[4:]

    parts = domain.split('.')

    if len(parts) > 2 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
        parts = parts[:-2]
    else:
        parts = parts[:-1]

    num_dots = len(parts) - 1

    if num_dots == 0:
        return 1
    elif num_dots == 1:
        return 0
    else:
        return -1


#6 HTTP & SSL check

import ssl
import datetime
from dateutil.parser import parse as parse_date
from dateutil import tz

# List of trusted certificate authorities
trusted_issuers = [
    "GeoTrust",
    "GoDaddy",
    "Network Solutions",
    "Thawte",
    "Comodo",
    "Doster",
    "VeriSign",
    "Google Trust Services",
    "DigiCert Inc",
    "GlobalSign nv-sa",
    "Sectigo Limited"
]

def get_certificate_info(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(3.0)
    
    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        return cert
    except Exception as e:
        print(f"Error retrieving certificate: {e}")
        return None

def is_trusted_issuer(issuer):
    for trusted in trusted_issuers:
        if trusted in issuer:
            return True
    return False

def get_certificate_age(cert):
    not_before = parse_date(cert['notBefore']).replace(tzinfo=tz.tzutc())
    current_time = datetime.utcnow().replace(tzinfo=tz.tzutc())
    age = (current_time - not_before).days / 365.25
    return age

def is_legitimate_url(url):
    if not url.startswith("https://"):
        return -1

    hostname = get_domain(url)
    cert = get_certificate_info(hostname)
    
    if cert is None:
        return -1

    issuer = cert.get('issuer', [])
    issuer_str = ' '.join(x[0][1] for x in issuer)
    age = get_certificate_age(cert)

    if is_trusted_issuer(issuer_str) and age <= 1:
        return 1
    elif is_trusted_issuer(issuer_str):
        return 0
    else:
        return -1

    
#  1 is legitimate
#  0 is suspicious
# -1 is fraud

#7 Request URL

from urllib.parse import urljoin
from bs4 import BeautifulSoup

def request_url(url):
    response = requests.get(url)
    global soup
    soup = BeautifulSoup(response.text, 'html.parser')
    total_urls = 0
    external_urls = 0
    domain = get_domain(url)

    for tag in soup.find_all(['img', 'script', 'iframe', 'link']):
        src = tag.get('src') or tag.get('href')
        if src:
            total_urls += 1
            full_url = urljoin(url, src)
            if get_domain(full_url) != domain:
                external_urls += 1

    if total_urls == 0:
        return 0

    percentage = (external_urls / total_urls) * 100

    if percentage < 22:
        return 1
    elif 22 <= percentage <= 61:
        return 0
    else:
        return -1
    

#8 URL of Anchor

def url_of_anchor(url):
    count = 0
    total_url = 0
    for tags in soup.find_all(['a']):
        href = tags.get('href')
        if href:
            total_url += 1
            if href in ['#','#content','#skip','JavaScript ::void(0)']:
                count += 1
    
    if total_url == 0:
        return 0
    percentage = (count/total_url)*100
    if percentage < 31:
        return 1
    elif 31<=percentage<=67:
        return 0
    else:
        return -1   


#9 Link of <Meta> <Link> and <Script>

def link_in_tags(url):
    total_links = 0
    external_links = 0
    for tag in soup.find_all(['meta', 'script', 'link']):
        src = tag.get('src') or tag.get('href') or tag.get('content')
        if src:
            total_links += 1
            full_url = urljoin(url, src)
            if get_domain(full_url) != get_domain(url):
                external_links += 1

    if total_links == 0:
        return 0

    percentage = (external_links / total_links) * 100
    if percentage < 17:
        return 1
    elif 17 <= percentage <= 81:
        return 0
    else:
        return -1
    

#10 Server Form Handler

def SFH(url):
    for tag in soup.find_all('form'):
        action = tag.get('action')
        if not action or action.strip().lower() == 'about:blank':
            return -1
        
        domain = get_domain(url)
        action_url = urljoin(url,action)
        action_domain = get_domain(action_url)
        if action_domain != domain:
            return 0
        
    return 1


#11 Age of Domain

import whois
from datetime import datetime

def age_of_domain(url):
    try:
        info = whois.whois(url)
        domain_creation = info.creation_date
        if domain_creation is None:
            return -1
        if isinstance(domain_creation, list):
            domain_creation = domain_creation[0]
        
        now = datetime.utcnow()
        url_age = (now.year - domain_creation.year)*12 
        if (now.month > domain_creation.month):
            url_age += (now.month - domain_creation.month)
        else:
            url_age += (now.month - domain_creation.month) + 12
    except Exception as e:
        return -1
    
    if(url_age >= 6):
        return 1
    else:
        return -1
    

#12 DNS Record

def dns_record(url):
    try:
        domain_name = get_domain(url)
        socket.gethostbyname(domain_name)
        return 1
    except socket.gaierror:
        return -1
    

#13 Port

standard_ports = {
    "http": 80,
    "https": 443,
    "ftp": 21
}

def check_port(url):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme  # e.g., 'http', 'https'
    port = parsed_url.port      
    
    if port is None:
        port = standard_ports.get(scheme)

    if port is not None and port != standard_ports.get(scheme):
        return -1
    else:
        return 1
    

#14 onmouseover

import requests
from bs4 import BeautifulSoup

def check_status_bar_customization(url):
    response = requests.get(url)

    soup = BeautifulSoup(response.text, 'html.parser')

    phishing_detected = False

    for tag in soup.find_all(True, onmouseover=True):
        onmouseover_content = tag['onmouseover']

        if 'window.status' in onmouseover_content:
            phishing_detected = True
            break
        
    for script in soup.find_all('script'):
        if script.string and 'window.status' in script.string:
            phishing_detected = True
            break

    if phishing_detected:
        return -1
    else:
        return 1


#15 Google Index

def google_index(url):

    url = get_domain(url)
    search_url = f"https://www.google.com/search?q=site:{url}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    response = requests.get(search_url, headers=headers)
    
    soup = BeautifulSoup(response.text, 'html.parser')
    
    if 'did not match any documents' in response.text:
        return -1
    else:
        return 1


#16 Statistical Report

import pandas as pd

def statistical_report(url):
    dataset = pd.read_csv("dataset_phishing.csv")
    if url in dataset['url'].values:
        return -1
    else:
        return 1
    
print(statistical_report("http://sheetdownload.com/"))


from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) 

@app.route('/process_url', methods=['POST'])
def process_url():
    data = request.json
    global url
    url = data.get('url')
    if url == "chrome://newtab/":
        return jsonify({"status": "skipped", "message": "New tab URL detected, processing skipped"})
    data = []
    data.append(is_ip_address(url))
    data.append(url_len(url))
    data.append(is_at_symbol(url))
    data.append(prefix_suffix(url))
    data.append(classify_url_by_subdomains(url))
    data.append(is_legitimate_url(url))
    data.append(request_url(url))
    data.append(url_of_anchor(url))
    data.append(link_in_tags(url))
    data.append(SFH(url))
    data.append(age_of_domain(url))
    data.append(dns_record(url))
    data.append(check_port(url))
    data.append(check_status_bar_customization(url))
    data.append(google_index(url))
    data.append(statistical_report(url))
    check = []
    check.append(data)
    forest_clf = joblib.load('random_forest_model.pkl')

    predictions = forest_clf.predict(check)

    print(url," is ",predictions)
    return jsonify({"status": "success", "url": url, "phishing_status": int(predictions[0])})

if __name__ == '__main__':
    app.run(debug=True)

