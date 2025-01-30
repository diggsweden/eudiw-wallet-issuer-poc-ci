package se.digg.eudiw.credentialissuer.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Arrays;

public enum CredentialFormatEnum {

    @JsonProperty("vc+sd-jwt")
    VC_SD_JWT("vc+sd-jwt"),

    @JsonProperty("mso_mdoc")
    MSO_MDOC("mso_mdoc");

    private final String format;

    CredentialFormatEnum(String format) {
        this.format = format;
    }

    public String getFormat() {
        return format;
    }

    public static CredentialFormatEnum fromString(String format) {
        return Arrays.stream(values())
                .filter(credFormat -> credFormat.format.equalsIgnoreCase(format))
                .findFirst()
                .orElse(null);
    }

    public static CredentialFormatEnum fromStringOrDefault(String format) {
        CredentialFormatEnum credentialFormatEnum = fromString(format);
        if (credentialFormatEnum == null) {
            return VC_SD_JWT;
        }
        return credentialFormatEnum;
    }

    public String toString() {
        return format;
    }
}
