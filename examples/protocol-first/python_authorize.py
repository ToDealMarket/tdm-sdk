import json
import urllib.request

GATEWAY_URL = "https://tdm.todealmarket.com/authorize"
SESSION_TOKEN = "tdm_session_replace_me"

body = {
    "requestId": "req_python_demo",
    "resourceId": "premium:api",
    "operation": "premium:api",
    "tokenOrUuid": "python-agent",
    "priceMinor": 5,
}

request = urllib.request.Request(
    GATEWAY_URL,
    data=json.dumps(body).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "X-TDM-Session-Token": SESSION_TOKEN,
    },
    method="POST",
)

with urllib.request.urlopen(request) as response:
    print(response.read().decode("utf-8"))

