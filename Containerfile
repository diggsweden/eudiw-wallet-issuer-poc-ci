FROM cgr.dev/chainguard/jre:latest@sha256:32f8e50d107dfb0a572a50b8fa57ce93505c94bf85bb15288ef72999ef0ea5b2

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
