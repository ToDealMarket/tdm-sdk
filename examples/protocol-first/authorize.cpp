#include <iostream>
#include <string>

int main() {
  const std::string body =
    "{\"requestId\":\"req_cpp_demo\",\"resourceId\":\"premium:api\","
    "\"operation\":\"premium:api\",\"tokenOrUuid\":\"cpp-agent\",\"priceMinor\":5}";

  std::cout << "POST https://tdm.todealmarket.com/authorize\n";
  std::cout << "Content-Type: application/json\n";
  std::cout << "X-TDM-Session-Token: tdm_session_replace_me\n\n";
  std::cout << body << "\n\n";
  std::cout << "Plug this body into libcurl, Boost.Beast, or your preferred HTTP client.\n";
  return 0;
}

