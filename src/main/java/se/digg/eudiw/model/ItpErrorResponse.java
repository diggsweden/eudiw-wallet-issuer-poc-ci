package se.digg.eudiw.model;

public record ItpErrorResponse(
    String status,
    String reason,
    String sessionId) {
}
