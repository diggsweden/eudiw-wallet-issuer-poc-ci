package se.oidc.oidfed.md;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.*;

/**
 * Description
 */
public class MetadataUtils {

  public static final ObjectMapper OBJECT_MAPPER = getOidcObjectMapper();

  public static final List<String> standardJwtClaims = List.of(
    "iss", "sub", "iat", "exp", "jti", "aud", "nbf"
  );

  public static ObjectMapper getOidcObjectMapper() {
    final ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true);
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    return objectMapper;
  }

  /**
   * Extract all claims that are not listed as standard JWT claims and are not present in the exclude data object
   *
   * @param dataObject Data object containing parameters that are not part of the extension set
   * @param payload payload of the JWT from which the extension claims are collected
   * @return JSON object map containing the extension claims
   * @throws JsonProcessingException JSON processing errors
   */
  public static Map<String, Object> getExtensionProperties(final Map<String, Object> payload, Object dataObject)
    throws JsonProcessingException {
    Objects.requireNonNull(payload, "Null payload is not allowed");
    dataObject = Optional.ofNullable(dataObject).orElse(new HashMap<>());

    final Map<String, Object> extensionObjectMap = new HashMap<>();
    final List<String> payloadClaims = new ArrayList<>(payload.keySet());
    final Map<String, Object> dataObjectMap = OBJECT_MAPPER.readValue(OBJECT_MAPPER.writeValueAsString(dataObject),
      new TypeReference<>() {
      });
    for (final String claimName : payloadClaims) {
      if (standardJwtClaims.contains(claimName)) {
        continue;
      }
      if (dataObjectMap.containsKey(claimName)) {
        continue;
      }
      // This parameter in the payload is not a standard JWT claim and not part of the defined data object members. Add to extensions
      extensionObjectMap.put(claimName, payload.get(claimName));
    }
    return extensionObjectMap;
  }

}
