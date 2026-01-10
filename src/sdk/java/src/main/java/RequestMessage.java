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

/**
 * TCP response message for HTTP-like communication.
 * Matches Python's ResponseMessage dataclass.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
class ResponseMessage {
    
    @JsonProperty("uuid")
    public String uuid = "";
    
    @JsonProperty("request_uri")
    public String request_uri = "";
    
    @JsonProperty("http_status")
    public int http_status = 0;
    
    @JsonProperty("body_msg_type")
    public String body_msg_type = "";
    
    @JsonProperty("body")
    public byte[] body = new byte[0];
    
    @JsonProperty("headers")
    public Map<String, String> headers = new HashMap<>();

    private static final ObjectMapper MAPPER = new ObjectMapper(new MessagePackFactory());

    /**
     * Deserialize TCP msgpack buffer.
     * Matches Python's deserialize() method.
     */
    public static ResponseMessage deserialize(byte[] buf) throws IOException {
        ResponseMessage msg = MAPPER.readValue(buf, ResponseMessage.class);
        // Ensure non-null defaults (matching Python's _convert_type behavior)
        if (msg.uuid == null) msg.uuid = "";
        if (msg.request_uri == null) msg.request_uri = "";
        if (msg.body_msg_type == null) msg.body_msg_type = "";
        if (msg.body == null) msg.body = new byte[0];
        if (msg.headers == null) msg.headers = new HashMap<>();
        return msg;
    }
}
