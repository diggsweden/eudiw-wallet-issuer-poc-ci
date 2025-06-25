package se.digg.eudiw.model;

public class ItbException extends RuntimeException {
  String status;
  String reason;
  String sessionId;

  public ItbException(String status, String reason, String sessionId) {
    this.status = status;
    this.reason = reason;
    this.sessionId = sessionId;
  }

  public String getStatus() {
    return status;
  }

  public String getReason() {
    return reason;
  }

  public String getSessionId() {
    return sessionId;
  }
}
