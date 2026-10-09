# Minimal local mail server: Postfix delivers directly to recipients' mail servers (MX),
# OpenDKIM signs outgoing mail for MAIL_DOMAIN.
FROM alpine:3.24
RUN apk add --no-cache postfix opendkim opendkim-utils ca-certificates
COPY entrypoint.sh /entrypoint.sh
EXPOSE 587
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
