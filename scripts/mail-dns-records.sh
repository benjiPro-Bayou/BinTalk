#!/usr/bin/env bash
# Prints the DNS records your domain needs so Gmail, Outlook, etc. accept mail from the local
# BinTalk mail server. Run after setting MAIL_DOMAIN in .env and restarting:
#   docker-compose up -d postfix api-server && ./scripts/mail-dns-records.sh
set -euo pipefail

DOMAIN=$(docker exec bintalk_postfix postconf -h mydomain)
HOST=$(docker exec bintalk_postfix postconf -h myhostname)
IP=$(curl -s --max-time 5 https://api.ipify.org || echo "<your public IP>")
DKIM=$(docker exec bintalk_postfix sh -c "cat /etc/opendkim/keys/$DOMAIN/bintalk.txt" |
  tr -d '\n\t' | sed -E 's/.*\( *//; s/ *\).*//; s/" *"//g; s/"//g')

cat <<OUT
Add these records in your DNS provider for $DOMAIN:

  Type  Name                           Value
  A     $HOST.                  $IP
  TXT   $DOMAIN.                       v=spf1 ip4:$IP -all
  TXT   bintalk._domainkey.$DOMAIN.    $DKIM
  TXT   _dmarc.$DOMAIN.                v=DMARC1; p=quarantine; rua=mailto:postmaster@$DOMAIN

Also ask your internet provider to set the reverse DNS (PTR) of $IP to $HOST
(Gmail rejects mail from IPs without a PTR record). Your IP should be static and allowed to
send on port 25.
OUT
if [[ "$DOMAIN" == *.local ]]; then
  echo
  echo "WARNING: $DOMAIN is not a real domain. Set MAIL_DOMAIN in .env first."
fi
