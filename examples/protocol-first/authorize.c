#include <stdio.h>

int main(void) {
  const char *body =
    "{\"requestId\":\"req_c_demo\",\"resourceId\":\"premium:api\","
    "\"operation\":\"premium:api\",\"tokenOrUuid\":\"c-agent\",\"priceMinor\":5}";

  puts("POST /authorize HTTP/1.1");
  puts("Host: tdm.todealmarket.com");
  puts("Content-Type: application/json");
  puts("X-TDM-Session-Token: tdm_session_replace_me");
  puts("");
  puts(body);
  puts("");
  puts("Send this body with libcurl or your HTTP client of choice.");
  return 0;
}

