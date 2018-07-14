import requests
import base64
import time
import json
import logging

import http.client

http.client.HTTPConnection.debuglevel = 1

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


destinationDevEUI = "70b3d54995bd3c5d"
url = "https://core.acklio.net:8080/v1/devices/"+destinationDevEUI+"/send"

print (url)

dwnCnt = 0

while True:
    payload = b"downlink #{}"
    dwnCnt += 1

    answer = {
        "fPort" : 2,
        "devEUI" : destinationDevEUI,
        "data": base64.b64encode(payload).decode('utf-8')
    }

    
    cookieContent = {"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MjU2Nzk1MTUsInVzZXJJbmZvIjp7ImFkbWluIjpmYWxzZSwidXNlcm5hbWUiOiJNT09DLVBMSURPIn19.p0o4eTyd-fvHXXpU8wXmolokFb_CBHpnKPWo8vZ_CTe8YCTaJYbdX_P043oOUaNzo8q9rP_LnD7DBSCLPJ7_NOJavj9sKLRU9vJDP0U7l5Bm1oK3fdlQX0hO9b2mMLQOOHQeC0h-KvAWg38oam9rKhX-Z42j35bOfMpPKKGgOK9NS5KdieDNds7lko6kl0tEgWjGNEi0ZwagigdNSO863aNC4qvGCjWEj4BLgQ2QcUB4Uy7LsFwCrUWST9nptx1gC2cVnm9G9iFvfyZ3QvHFw9XgPjA1_67suFKEw_2rdmlc0s4JH8oaufLvLtcVhKoBZCItN192hWHEO0xe0Kh4mQ"};
                                   

    print (cookieContent)
    
    print (requests.post(url, data=json.dumps(answer), cookies=cookieContent))

    time.sleep(60)
