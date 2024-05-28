import argparse
import requests
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress only the InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

def read_file(filepath):
    with open(filepath, 'r') as file:
        return file.read().splitlines()

def check_sql_error(response_text):
    sql_error_patterns = [
        "SQL syntax", "mysql_fetch", "sql error", "sql syntax", "SQL statement", "SQL function", "SQL column",
        "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated", "internal server error", "SqlConnection"
    ]
    for pattern in sql_error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False

def send_request(url, headers=None):
    start_time = time.time()
    try:
        response = requests.get(url, headers=headers, verify=False)
        response_time = time.time() - start_time
        return url, headers, response, response_time
    except requests.exceptions.RequestException as e:
        return url, headers, None, None

def process_response(url, headers, response, response_time):
    if response is None:
        pass
        #print(f"Request failed for {url} with headers {headers}")
    else:
        if check_sql_error(response.text) or (response_time and response_time > 4):
            header_info = f" with header {headers}" if headers else ""
            print(f"{Fore.RED}SQL syntax error or timeout detected: {url}{header_info}{Style.RESET_ALL}")
            print(f"{Fore.RED}Response: {1}{Style.RESET_ALL}")
            #print(f"{Fore.RED}Response: {response.text}{Style.RESET_ALL}")

def send_payloads(urls, payloads, headers_to_test, header_payloads):
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []

        for url in urls:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            paths = parsed_url.path.strip('/').split('/')
            query_params = parse_qs(parsed_url.query)

            # Send payloads for each path segment
            for i, path in enumerate(paths):
                for payload in payloads:
                    new_paths = paths.copy()
                    new_paths[i] += payload
                    test_url = f"{base_url}/{'/'.join(new_paths)}"
                    if parsed_url.query:
                        test_url += f"?{parsed_url.query}"
               #    print(f"Queueing request to: {test_url}")
                    futures.append(executor.submit(send_request, test_url))

            # Send payloads for each parameter value
            for param in query_params:
                for payload in payloads:
                    modified_params = query_params.copy()
                    modified_params[param] = payload
                    new_query = urlencode(modified_params, doseq=True)
                    test_url = urlunparse(parsed_url._replace(query=new_query))
              #     print(f"Queueing request to: {test_url}")
                    futures.append(executor.submit(send_request, test_url))

            # Send payloads in headers
            for header in headers_to_test:
                for header_payload in header_payloads:
                    headers = {header: header_payload}
                #   print(f"Queueing request to: {url} with header {header}: {header_payload}")
                    futures.append(executor.submit(send_request, url, headers=headers))

        for future in as_completed(futures):
            url, headers, response, response_time = future.result()
            process_response(url, headers, response, response_time)

def main():
    # Initialize colorama
    init(autoreset=True)

    parser = argparse.ArgumentParser(description="SQL Injection Payload Tester")
    parser.add_argument('-payloads', required=True, help='Path to the payloads txt file')
    parser.add_argument('-urls', required=True, help='Path to the urls txt file')
    parser.add_argument('-headers_to_test', required=True, help='Path to the headers to test txt file')
    parser.add_argument('-header_payloads', required=True, help='Path to the header payloads txt file')
    args = parser.parse_args()

    payloads = read_file(args.payloads)
    urls = read_file(args.urls)
    headers_to_test = read_file(args.headers_to_test)
    header_payloads = read_file(args.header_payloads)

    send_payloads(urls, payloads, headers_to_test, header_payloads)

if __name__ == "__main__":
    main()
