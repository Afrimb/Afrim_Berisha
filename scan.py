import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

s = requests.Session()

# Function to get all forms
def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

# Function to extract form details
def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []
    
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })
    
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

# Function to check if response is vulnerable
def vulnerable(response):
    errors = [
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax",
        "warning: mysql",
        "unexpected end of SQL command",
        "odbc driver",
        "microsoft ole db",
        "sql syntax",
        "mysql_fetch"
    ]
    
    content = response.text.lower()
    for error in errors:
        if error in content:
            return True
    return False

# Main scanning function
def scan_sql_injection(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}")
    
    for form in forms:
        details = form_details(form)
        
        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag.get("value"):
                    data[input_tag['name']] = input_tag.get("value", "") + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"
            
            if details["method"].lower() == "post":
                res = s.post(url, data=data)
            else:
                res = s.get(url, params=data)
            
            if vulnerable(res):
                print(f"\n[!] SQL Injection vulnerability detected!")
                print(f"[!] Payload used: {i}")
                print(f"[!] Form action: {details['action']}")
                print(f"[!] Method: {details['method']}")
                return True
    
    return False

# Main execution
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        print(f"[*] Scanning {target_url} for SQL injection vulnerabilities...")
        if scan_sql_injection(target_url):
            print("\n[!] The website is VULNERABLE to SQL injection!")
        else:
            print("\n[-] The website seems secure against SQL injection.")
    else:
        print("Usage: python scan.py <url>")
        print("Example: python scan.py http://testsite.com/page.php?id=1")