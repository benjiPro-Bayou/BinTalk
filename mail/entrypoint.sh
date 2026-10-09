#!/bin/sh
# Configures and starts the local mail server.
#   MAIL_DOMAIN    domain in the From address; DKIM key is generated for it (default bintalk.local)
#   MAIL_HOSTNAME  name used when talking to other mail servers (default mail.$MAIL_DOMAIN)
#   MAIL_COPY_TO   also send a copy of every email here (default: the Mailpit dev inbox)
# Only containers on the private Docker network may send (no open relay, no authentication).
set -eu

DOMAIN="${MAIL_DOMAIN:-bintalk.local}"
HOST="${MAIL_HOSTNAME:-mail.$DOMAIN}"
COPY_TO="${MAIL_COPY_TO:-}"
SELECTOR=bintalk
KEYDIR="/etc/opendkim/keys/$DOMAIN"

postconf -e \
  "myhostname=$HOST" "mydomain=$DOMAIN" "myorigin=$DOMAIN" "smtp_helo_name=$HOST" \
  "mydestination=" "local_recipient_maps=" "local_transport=error:local delivery is disabled" \
  "inet_interfaces=all" "inet_protocols=ipv4" \
  "mynetworks=127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16" \
  "smtpd_relay_restrictions=permit_mynetworks,reject" \
  "smtpd_recipient_restrictions=permit_mynetworks,reject" \
  "smtp_tls_security_level=may" "smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt" \
  "smtp_tls_loglevel=1" "smtpd_tls_security_level=none" \
  "message_size_limit=26214400" \
  "maximal_queue_lifetime=1h" "bounce_queue_lifetime=1h" \
  "maillog_file=/dev/stdout"

# Port 587 for the API (inside the Docker network only; not published to the host).
postconf -M "submission/inet=submission inet n - n - - smtpd"

if [ -n "$COPY_TO" ]; then
  postconf -e "always_bcc=$COPY_TO" "transport_maps=texthash:/etc/postfix/bintalk_transport"
  echo "mailpit.internal smtp:[mailpit]:1025" > /etc/postfix/bintalk_transport
fi

# DKIM: generate a key once per domain (kept in a volume) and sign everything we send.
mkdir -p "$KEYDIR"
if [ ! -f "$KEYDIR/$SELECTOR.private" ]; then
  opendkim-genkey -b 2048 -d "$DOMAIN" -s "$SELECTOR" -D "$KEYDIR"
  echo "mail: generated DKIM key for $DOMAIN (selector $SELECTOR)"
fi
chown -R opendkim:opendkim /etc/opendkim/keys
cat > /etc/opendkim/opendkim.conf <<CONF
Domain                  $DOMAIN
Selector                $SELECTOR
KeyFile                 $KEYDIR/$SELECTOR.private
Socket                  inet:8891@127.0.0.1
Mode                    s
Canonicalization        relaxed/simple
SubDomains              yes
UserID                  opendkim
Syslog                  no
# Sign mail submitted from the Docker network (the API), not only from localhost.
InternalHosts           127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
CONF
postconf -e "milter_protocol=6" "milter_default_action=accept" \
  "smtpd_milters=inet:127.0.0.1:8891" "non_smtpd_milters=inet:127.0.0.1:8891"
opendkim -x /etc/opendkim/opendkim.conf

echo "mail: delivering directly for $DOMAIN as $HOST${COPY_TO:+ (copy of every email to $COPY_TO)}"
exec postfix start-fg
