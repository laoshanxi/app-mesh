package appmesh;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.msgpack.jackson.dataformat.MessagePackFactory;

/** TCP request message. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RequestMessage {
    
    @JsonProperty("uuid")
    public String uuid = "";
    
    @JsonProperty("request_uri")
    public String requestUri = "";
    
    @JsonProperty("http_method")
    public String httpMethod = "";
    
    @JsonProperty("client_addr")
    public String clientAddr = "";
    
    @JsonProperty("body")
    public byte[] body = new byte[0];
    
    @JsonProperty("headers")
    public Map<String, String> headers = new HashMap<>();
    
    @JsonProperty("query")
    public Map<String, String> query = new HashMap<>();

    private static final ObjectMapper MAPPER = new ObjectMapper(new MessagePackFactory());

    /** Serialize to MessagePack bytes. */
    public byte[] serialize() throws IOException {
        return MAPPER.writeValueAsBytes(this);
    }
}
