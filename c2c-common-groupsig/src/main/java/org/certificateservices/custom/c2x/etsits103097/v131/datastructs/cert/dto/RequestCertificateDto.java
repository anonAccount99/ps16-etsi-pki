package org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.dto;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Objects;

public class RequestCertificateDto implements Serializable {
    private static final long serialVersionUID = 1L;

    private String id;
    private int validityPeriod;
    private int region_code;
    private int subjectAssuranceLevel;
    private int subjectConfidenceLevel;
    private String signingPublicKey;
    private String encryptionPublicKey;

    public RequestCertificateDto() {}

    public RequestCertificateDto(String id,
                                 int validityPeriod,
                                 int region_code,
                                 int subjectAssuranceLevel,
                                 int subjectConfidenceLevel,
                                 String signingPublicKey,
                                 String encryptionPublicKey) {
        this.id = id;
        this.validityPeriod = validityPeriod;
        this.region_code = region_code;
        this.subjectAssuranceLevel = subjectAssuranceLevel;
        this.subjectConfidenceLevel = subjectConfidenceLevel;
        this.signingPublicKey = signingPublicKey;
        this.encryptionPublicKey = encryptionPublicKey;
    }

    public static PublicKey decodePublicKey(String base64Key) throws Exception {
        byte[] keyBytes = java.util.Base64.getDecoder().decode(base64Key);
        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(spec);
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getValidityPeriod() {
        return validityPeriod;
    }

    public void setValidityPeriod(int validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    public int getRegion_code() {
        return region_code;
    }

    public void setRegion_code(int region_code) {
        this.region_code = region_code;
    }

    public int getSubjectAssuranceLevel() {
        return subjectAssuranceLevel;
    }

    public void setSubjectAssuranceLevel(int subjectAssuranceLevel) {
        this.subjectAssuranceLevel = subjectAssuranceLevel;
    }

    public int getSubjectConfidenceLevel() {
        return subjectConfidenceLevel;
    }

    public void setSubjectConfidenceLevel(int subjectConfidenceLevel) {
        this.subjectConfidenceLevel = subjectConfidenceLevel;
    }

    public String getSigningPublicKey() {
        return signingPublicKey;
    }

    public void setSigningPublicKey(String signingPublicKey) {
        this.signingPublicKey = signingPublicKey;
    }

    public String getEncryptionPublicKey() {
        return encryptionPublicKey;
    }

    public void setEncryptionPublicKey(String encryptionPublicKey) {
        this.encryptionPublicKey = encryptionPublicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        RequestCertificateDto that = (RequestCertificateDto) o;
        return region_code == that.region_code && subjectAssuranceLevel == that.subjectAssuranceLevel && subjectConfidenceLevel == that.subjectConfidenceLevel && Objects.equals(id, that.id) && Objects.equals(signingPublicKey, that.signingPublicKey) && Objects.equals(encryptionPublicKey, that.encryptionPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, region_code, subjectAssuranceLevel, subjectConfidenceLevel, signingPublicKey, encryptionPublicKey);
    }

    @Override
    public String toString() {
        return "RequestCertificateDto{" +
                "id='" + id + '\'' +
                ", region_code=" + region_code +
                ", subjectAssuranceLevel=" + subjectAssuranceLevel +
                ", subjectConfidenceLevel=" + subjectConfidenceLevel +
                ", signingPublicKey='" + signingPublicKey + '\'' +
                ", encryptionPublicKey='" + encryptionPublicKey + '\'' +
                '}';
    }
}
