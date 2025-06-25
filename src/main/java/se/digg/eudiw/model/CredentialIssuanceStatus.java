package se.digg.eudiw.model;

public record CredentialIssuanceStatus(
    String status,
    String reason,
    String sessionId) {
}
