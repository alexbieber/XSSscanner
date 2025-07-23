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


