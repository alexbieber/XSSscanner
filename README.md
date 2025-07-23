# XSS Vulnerability Scanner

This is a Python script designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications. It identifies input forms on a given URL, injects common XSS payloads, and analyzes the server's response to determine if the website is vulnerable.

## Features

- **Form Detection**: Automatically identifies HTML forms and their input fields.
- **Payload Injection**: Injects a predefined XSS payload into identified input fields.
- **Response Analysis**: Checks the server's response for the presence of the injected payload, indicating a potential XSS vulnerability.
- **Reflected XSS Detection**: Primarily focuses on detecting reflected XSS vulnerabilities.

## How it Works

The script performs the following steps:

1. **Fetches Forms**: It sends an HTTP GET request to the target URL and parses the HTML content to find all `<form>` tags.
2. **Extracts Form Details**: For each form, it extracts the `action` URL, `method` (GET/POST), and details of all input fields (name, type, value).
3. **Injects Payloads**: It constructs a data payload by inserting a known XSS string (e.g., `<script>alert(\'XSS\')</script>`) into each text-based input field.
4. **Submits Forms**: It then submits the modified form data to the target URL using either GET or POST requests, depending on the form's method.
5. **Analyzes Response**: Finally, it checks if the injected XSS payload is reflected in the HTML response content. If found, it indicates a potential XSS vulnerability.

## Usage

### Prerequisites

- Python 3.x
- `requests` library (`pip install requests`)
- `BeautifulSoup4` library (`pip install beautifulsoup4`)

### Running the Scanner

To run the XSS scanner, execute the script from your terminal, providing the target URL as an argument:

```bash
python xss_scanner.py <target_url>
```

**Example:**

```bash
python xss_scanner.py http://example.com/vulnerable_page.html
```

## Script Details

### `xss_scanner.py`

```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """Returns the HTML details of a form, including action, method and input tags"""
    details = {}
    # get the form action (target URL)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all input tags that are not submit / reset button
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything in the dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def scan_xss(url):
    """Scans the given URL for XSS vulnerabilities"""
    # get all forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<script>alert(\'XSS\')</script>"
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = requests.get(url).content
        soup = BeautifulSoup(content, "html.parser")
        # the target URL
        target_url = urljoin(url, form_details["action"])
        # all input fields
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = js_script
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        print(f"[+] Submitting to {target_url}")
        print(f"[+] Data: {data}")
        if form_details["method"] == "post":
            res = requests.post(target_url, data=data)
        elif form_details["method"] == "get":
            res = requests.get(target_url, params=data)
        # detect if the JavaScript part is in the HTML response
        if js_script in res.content.decode():
            print(f"[!!!] XSS Detected on {target_url}")
            print(f"[*] Form details:")
            print(form_details)
            is_vulnerable = True
    return is_vulnerable

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        if scan_xss(url):
            print("[+] XSS vulnerability detected.")
        else:
            print("[-] No XSS vulnerability detected.")
    else:
        print("Usage: python xss_scanner.py <url>")
```

## Limitations

- This script primarily focuses on reflected XSS and may not fully detect stored or DOM-based XSS vulnerabilities without further enhancements (e.g., persistent storage analysis, headless browser execution).
- It uses a single, basic XSS payload. More sophisticated payloads and encoding variations could be added for more comprehensive testing.
- It does not handle authentication or session management, so it's best used on publicly accessible pages or after manual authentication.

## Disclaimer

This script is for educational and ethical hacking purposes only. Do not use it to test websites without explicit permission from the owner. Unauthorized scanning is illegal and unethical.
