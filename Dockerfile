FROM alpine:3.12
COPY /build/bin/production-readiness /
ENTRYPOINT ["/production-readiness"]
