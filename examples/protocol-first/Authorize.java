import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public final class Authorize {
  public static void main(String[] args) throws Exception {
    String body = "{\"requestId\":\"req_java_demo\",\"resourceId\":\"premium:api\",\"operation\":\"premium:api\",\"tokenOrUuid\":\"java-agent\",\"priceMinor\":5}";

    HttpRequest request = HttpRequest.newBuilder()
      .uri(URI.create("https://tdm.todealmarket.com/authorize"))
      .header("Content-Type", "application/json")
      .header("X-TDM-Session-Token", "tdm_session_replace_me")
      .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
      .build();

    HttpClient client = HttpClient.newHttpClient();
    HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
    byte[] raw = response.body().readAllBytes();
    System.out.println(new String(raw, StandardCharsets.UTF_8));
  }
}

