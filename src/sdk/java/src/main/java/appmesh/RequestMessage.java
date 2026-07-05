package appmesh;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * TCP request message for HTTP-like communication.
 * Matches Python's RequestMessage dataclass.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RequestMessage {
    
    @JsonProperty("uuid")
    public String uuid = "";
    
    @JsonProperty("request_uri")
    public String request_uri = "";
    
    @JsonProperty("http_method")
    public String http_method = "";
    
    @JsonProperty("client_addr")
    public String client_addr = "";
    
    @JsonProperty("body")
    public byte[] body = new byte[0];
    
    @JsonProperty("headers")
    public Map<String, String> headers = new HashMap<>();
    
    @JsonProperty("query")
    public Map<String, String> query = new HashMap<>();

    private static final ObjectMapper MAPPER = new ObjectMapper(new MessagePackFactory());

    /**
     * Serialize request message to bytes using MessagePack.
     * Matches Python's serialize() method.
     */
    public byte[] serialize() throws IOException {
        return MAPPER.writeValueAsBytes(this);
    }
}
