package se.digg.eudiw.credentialissuer.model;

import java.util.Objects;

public class CredentialParam {
    CredentialFormatEnum format;
    JwtProof proof;
    String vct;

    public CredentialParam() {
        this.format = CredentialFormatEnum.VC_SD_JWT;
        this.proof = null;
        this.vct = null;
    }

    public CredentialParam(CredentialFormatEnum format, JwtProof proof, String vct) {
        this.format = format;
        this.proof = proof;
        this.vct = vct;
    }

    public CredentialFormatEnum getFormat() {
        return format;
    }

    public void setFormat(CredentialFormatEnum format) {
        this.format = format;
    }

    public JwtProof getProof() {
        return proof;
    }

    public void setProof(JwtProof proof) {
        this.proof = proof;
    }

    public String getVct() {
        return vct;
    }

    public void setVct(String vct) {
        this.vct = vct;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CredentialParam that = (CredentialParam) o;
        return format == that.format && Objects.equals(proof, that.proof) && Objects.equals(vct, that.vct);
    }

    @Override
    public int hashCode() {
        return Objects.hash(format, proof, vct);
    }

    @Override
    public String toString() {
        return "CredentialParam{" +
                "format=" + format +
                ", proof=" + proof +
                ", vct='" + vct + '\'' +
                '}';
    }
}
