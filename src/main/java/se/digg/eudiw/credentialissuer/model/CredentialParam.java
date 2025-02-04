package se.digg.eudiw.credentialissuer.model;

import jakarta.validation.constraints.NotNull;
import org.springframework.validation.annotation.Validated;

import java.util.Objects;

@Validated
public class CredentialParam {
    CredentialFormatEnum format;
    @NotNull
    JwtProof proof;
    String vct;
    String doctype;

    public CredentialParam() {
        this.format = CredentialFormatEnum.VC_SD_JWT;
        this.proof = null;
        this.vct = null;
        this.doctype = null;
    }

    public CredentialParam(CredentialFormatEnum format, JwtProof proof, String vct, String doctype) {
        this.format = format;
        this.proof = proof;
        this.vct = vct;
        this.doctype = doctype;
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

    public String getDoctype() {
        return doctype;
    }

    public void setDoctype(String doctype) {
        this.doctype = doctype;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CredentialParam that = (CredentialParam) o;
        return format == that.format && Objects.equals(proof, that.proof) && Objects.equals(vct, that.vct) && Objects.equals(doctype, that.doctype);
    }

    @Override
    public int hashCode() {
        return Objects.hash(format, proof, vct, doctype);
    }

    @Override
    public String toString() {
        return "CredentialParam{" +
                "format=" + format +
                ", proof=" + proof +
                ", vct='" + vct + '\'' +
                ", doctype='" + doctype + '\'' +
                '}';
    }
}
