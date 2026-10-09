#!/usr/bin/env bash
# End-to-end smoke test for the BinTalk API, run against the Nginx gateway.
# Usage: BINTALK_DISPOSABLE=1 ./scripts/smoke-test.sh [base_url]   (default: https://localhost)
# Requires: curl, jq, docker, and the stack running (docker compose up -d).
# With CHAPA_MOCK_URL set (a mock Chapa server that marks a payment paid at <url>/pay/<tx_ref>),
# companies are activated by paying; otherwise a platform admin approves them.
#
# It creates accounts, sends email, suspends a user and temporarily grants admin rights, so it
# must only run against a disposable stack; BINTALK_DISPOSABLE=1 confirms that.

set -u
if [[ "${BINTALK_DISPOSABLE:-}" != "1" ]]; then
  echo "This test changes data on the target stack (accounts, admin rights, email)."
  echo "Run it only against a disposable stack, with BINTALK_DISPOSABLE=1."
  exit 2
fi
BASE="${1:-https://localhost}"
API="$BASE/api/v1"
JSON=(-H "Content-Type: application/json")
RUN=$RANDOM
PASS=0
FAIL=0

check() { # check <description> <expected> <actual>
  if [[ "$3" == "$2" ]]; then
    echo "  PASS  $1"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $1 (expected '$2', got '$3')"
    FAIL=$((FAIL + 1))
  fi
}
status() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }
signup() { # signup <owner> <company>: registers a company on the landing page
  curl -sk -X POST "$API/public/signup" "${JSON[@]}" -d "{\"company_name\":\"$2 $RUN\",\"plan_code\":\"starter\",
    \"billing_cycle\":\"monthly\",\"full_name\":\"$1\",\"username\":\"$1$RUN\",\"email\":\"$1$RUN@example.com\",\"password\":\"password123\"}"
}
invite() { # invite <name> <auth header...>: prints the invitation token
  curl -sk -X POST "$API/admin/invitations" "${JSON[@]}" "${@:2}" -d "{\"email\":\"$1$RUN@example.com\"}" \
    | jq -r '.invite_link // ""' | sed 's/.*#invite=//'
}
register() { # register <name> <invitation token>
  curl -sk -X POST "$API/auth/register" "${JSON[@]}" -d "{\"invite_token\":\"$2\",\"username\":\"$1$RUN\",
    \"email\":\"$1$RUN@example.com\",\"password\":\"password123\",\"full_name\":\"$1\"}"
}
login() {
  curl -sk -X POST "$API/auth/login" "${JSON[@]}" -d "{\"email\":\"$1$RUN@example.com\",\"password\":\"password123\"}"
}

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "Missing required tool: $tool"; exit 1; }
done

TMP_FILE=$(mktemp)
# Runs on every exit, including failures and Ctrl-C: never leave a test account with a known
# password holding admin rights.
cleanup() {
  docker exec bintalk_postgres psql -U bintalk -d bintalk_db -qc \
    "UPDATE users SET role = 'user' WHERE email = 'root$RUN@example.com'" >/dev/null 2>&1
  rm -f "$TMP_FILE"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "== Health"
check "gateway and API are up" "healthy" "$(curl -sk "$BASE/health" | jq -r .status)"
check "status requires login" "401" "$(status "$API/encryption/status")"

echo "== Companies, payments and invitations"
check "plans are published" "true" "$(curl -sk "$API/public/plans" | jq '.plans | length > 0')"
SIGNUP_A=$(signup alice Acme)
COMPANY_A=$(jq -r .company.id <<<"$SIGNUP_A")
check "company sign-up" "alice$RUN@example.com" "$(jq -r .company.contact_email <<<"$SIGNUP_A")"
SIGNUP_ROOT=$(signup root Platform)
check "owners cannot sign in before activation" "company_inactive" "$(login alice | jq -r .code)"
BODY="{\"invite_token\":\"nope\",\"username\":\"mallory$RUN\",\"email\":\"mallory$RUN@example.com\",\"password\":\"password123\",\"full_name\":\"M\"}"
check "registration needs an invitation" "400" "$(status -X POST "$API/auth/register" "${JSON[@]}" -d "$BODY")"

# A platform admin (root, owner of another company) runs the service.
docker exec bintalk_api_server ./api-server make-admin "root$RUN@example.com" >/dev/null 2>&1
LOGIN_ROOT=$(login root)
AUTH_ADMIN=(-H "Authorization: Bearer $(jq -r .token <<<"$LOGIN_ROOT")")
ROOT=$(jq -r .user.id <<<"$LOGIN_ROOT")
check "platform admins can always sign in" "admin" "$(jq -r .user.role <<<"$LOGIN_ROOT")"

TX_A=$(jq -r '.tx_ref // ""' <<<"$SIGNUP_A")
if [[ -n "${CHAPA_MOCK_URL:-}" && -n "$TX_A" ]]; then
  check "sign-up opens a Chapa checkout" "true" "$(jq '.checkout_url | length > 0' <<<"$SIGNUP_A")"
  check "unpaid checkout stays pending" "pending" "$(curl -sk "$API/public/payments/$TX_A" | jq -r .status)"
  curl -s "$CHAPA_MOCK_URL/pay/$TX_A" >/dev/null
  PAID=$(curl -sk "$API/public/payments/$TX_A")
  check "verified payment activates the company" "success active" "$(jq -r '.status + " " + .company_status' <<<"$PAID")"
  check "verifying again changes nothing" "success" "$(curl -sk "$API/public/payments/$TX_A" | jq -r .status)"
  check "a callback for an unknown payment is ignored" "200" "$(status "$API/public/payments/chapa/callback?trx_ref=btk-unknown")"
else
  check "platform admin approves a company" "active" "$(curl -sk -X PUT "$API/platform/companies/$COMPANY_A" "${JSON[@]}" "${AUTH_ADMIN[@]}" \
    -d '{"status":"active","extend_months":1}' | jq -r .company.status)"
fi
check "platform admins list companies" "true" "$(curl -sk "$API/platform/companies" "${AUTH_ADMIN[@]}" | jq --arg id "$COMPANY_A" '[.companies[] | select(.id == $id)] | length == 1')"

LOGIN_A=$(login alice)
TOKEN_A=$(jq -r .token <<<"$LOGIN_A")
AUTH_A=(-H "Authorization: Bearer $TOKEN_A")
ALICE=$(jq -r .user.id <<<"$LOGIN_A")
REFRESH_A=$(jq -r .refresh_token <<<"$LOGIN_A")
check "owner signs in once the company is active" "owner Acme $RUN" "$(jq -r '.user.company_role + " " + .company.name' <<<"$LOGIN_A")"
BODY="{\"email\":\"alice$RUN@example.com\",\"password\":\"wrong-password\"}"
check "wrong password rejected" "401" "$(status -X POST "$API/auth/login" "${JSON[@]}" -d "$BODY")"

INVITE_B=$(invite bob "${AUTH_A[@]}")
check "invitation link describes the company" "Acme $RUN" "$(curl -sk "$API/public/invitations/$INVITE_B" | jq -r .company_name)"
BODY="{\"invite_token\":\"$INVITE_B\",\"username\":\"bobx$RUN\",\"email\":\"other$RUN@example.com\",\"password\":\"password123\",\"full_name\":\"B\"}"
check "invitation only works for its email address" "400" "$(status -X POST "$API/auth/register" "${JSON[@]}" -d "$BODY")"
check "invited colleague joins the company" "member" "$(register bob "$INVITE_B" | jq -r .user.company_role)"
check "an invitation works once" "400" "$(status -X POST "$API/auth/register" "${JSON[@]}" \
  -d "{\"invite_token\":\"$INVITE_B\",\"username\":\"bob2$RUN\",\"email\":\"bob$RUN@example.com\",\"password\":\"password123\",\"full_name\":\"B\"}")"
LOGIN_B=$(login bob)
TOKEN_B=$(jq -r .token <<<"$LOGIN_B")
BOB=$(jq -r .user.id <<<"$LOGIN_B")
AUTH_B=(-H "Authorization: Bearer $TOKEN_B")
check "login returns a token" "true" "$(jq '.token | length > 20' <<<"$LOGIN_A")"
check "members cannot invite" "403" "$(status -X POST "$API/admin/invitations" "${JSON[@]}" "${AUTH_B[@]}" -d '{"email":"x@example.com"}')"
check "company admins cannot open the platform API" "403" "$(status "$API/platform/companies" "${AUTH_A[@]}")"
check "company admins see their billing" "starter" "$(curl -sk "$API/admin/company" "${AUTH_A[@]}" | jq -r .company.plan.code)"

echo "== Isolation between companies"
check "search does not find other companies' people" "0" "$(curl -sk "$API/users/search?q=bob$RUN" "${AUTH_ADMIN[@]}" | jq -r .total)"
check "profiles of other companies are hidden" "404" "$(status "$API/users/$ALICE" "${AUTH_ADMIN[@]}")"
BODY="{\"receiver_id\":\"$ALICE\",\"content\":\"hi\",\"message_type\":\"text\"}"
check "cannot message another company" "404" "$(status -X POST "$API/messages" "${JSON[@]}" "${AUTH_ADMIN[@]}" -d "$BODY")"
BODY="{\"receiver_id\":\"$ALICE\",\"media\":\"audio\"}"
check "cannot call another company" "404" "$(status -X POST "$API/calls" "${JSON[@]}" "${AUTH_ADMIN[@]}" -d "$BODY")"
check "company admins only see their own members" "0" "$(curl -sk "$API/admin/users?q=root$RUN" "${AUTH_A[@]}" | jq -r .total)"

echo "== Encryption"
check "encryption status operational" "operational" "$(curl -sk "$API/encryption/status" "${AUTH_A[@]}" | jq -r .status)"
check "public key published" "RSA-OAEP" "$(curl -sk "$API/encryption/public-key" | jq -r .algorithm)"
CIPHERTEXT=$(curl -sk -X POST "$API/encryption/encrypt" "${AUTH_A[@]}" "${JSON[@]}" -d '{"plaintext":"vault me"}' | jq -r .ciphertext)
check "vault encrypt/decrypt round trip" "vault me" "$(curl -sk -X POST "$API/encryption/decrypt" "${AUTH_A[@]}" "${JSON[@]}" \
  -d "{\"ciphertext\":\"$CIPHERTEXT\"}" | jq -r .plaintext)"
check "other user cannot decrypt" "403" "$(status -X POST "$API/encryption/decrypt" "${AUTH_B[@]}" "${JSON[@]}" \
  -d "{\"ciphertext\":\"$CIPHERTEXT\"}")"

echo "== Users"
check "search finds bob" "1" "$(curl -sk "$API/users/search?q=bob$RUN" "${AUTH_A[@]}" | jq -r .total)"
check "other users' email hidden" "" "$(curl -sk "$API/users/$BOB" "${AUTH_A[@]}" | jq -r .user.email)"
check "update own profile" "Alice Updated" "$(curl -sk -X PUT "$API/users/$ALICE" "${AUTH_A[@]}" "${JSON[@]}" \
  -d '{"full_name":"Alice Updated"}' | jq -r .user.full_name)"
check "cannot update another user" "403" "$(status -X PUT "$API/users/$BOB" "${AUTH_A[@]}" "${JSON[@]}" -d '{"full_name":"x"}')"

echo "== Direct messages"
SENT=$(curl -sk -X POST "$API/messages" "${AUTH_A[@]}" "${JSON[@]}" \
  -d "{\"receiver_id\":\"$BOB\",\"content\":\"hello bob\",\"message_type\":\"text\"}")
MESSAGE=$(jq -r .message.id <<<"$SENT")
CONVERSATION=$(jq -r .conversation_id <<<"$SENT")
check "send message" "hello bob" "$(jq -r .message.content <<<"$SENT")"
check "recipient reads message" "hello bob" "$(curl -sk "$API/messages/$CONVERSATION" "${AUTH_B[@]}" | jq -r '.messages[0].content')"
check "users cannot post system messages" "400" "$(status -X POST "$API/messages" "${AUTH_A[@]}" "${JSON[@]}" \
  -d "{\"receiver_id\":\"$BOB\",\"content\":\"IT notice\",\"message_type\":\"system\"}")"
CLIENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr 'A-Z' 'a-z')
BODY="{\"receiver_id\":\"$BOB\",\"content\":\"once\",\"message_type\":\"text\",\"client_id\":\"$CLIENT_ID\"}"
FIRST=$(curl -sk -X POST "$API/messages" "${AUTH_A[@]}" "${JSON[@]}" -d "$BODY" | jq -r .message.id)
check "a retried send returns the original message" "$FIRST" "$(curl -sk -X POST "$API/messages" "${AUTH_A[@]}" "${JSON[@]}" -d "$BODY" | jq -r .message.id)"
check "recipient cannot delete sender's message" "403" "$(status -X DELETE "$API/messages/$MESSAGE" "${AUTH_B[@]}")"
check "sender deletes message" "true" "$(curl -sk -X DELETE "$API/messages/$MESSAGE" "${AUTH_A[@]}" | jq -r .deleted)"

echo "== Groups"
GROUP=$(curl -sk -X POST "$API/groups" "${AUTH_A[@]}" "${JSON[@]}" -d '{"name":"Team","group_type":"team"}' | jq -r .group.id)
check "non-member cannot see group" "404" "$(status "$API/groups/$GROUP" "${AUTH_B[@]}")"
BODY="{\"user_id\":\"$BOB\",\"role\":\"member\"}"
check "admin adds member" "member" "$(curl -sk -X POST "$API/groups/$GROUP/members" "${AUTH_A[@]}" "${JSON[@]}" -d "$BODY" | jq -r .member.role)"
curl -sk -X POST "$API/messages" "${AUTH_B[@]}" "${JSON[@]}" \
  -d "{\"group_id\":\"$GROUP\",\"content\":\"hi team\",\"message_type\":\"text\"}" >/dev/null
check "group message visible to members" "hi team" "$(curl -sk "$API/messages/$GROUP" "${AUTH_A[@]}" | jq -r '.messages[0].content')"
check "member cannot update group" "403" "$(status -X PUT "$API/groups/$GROUP" "${AUTH_B[@]}" "${JSON[@]}" -d '{"name":"x"}')"
CHANNEL=$(curl -sk -X POST "$API/groups" "${AUTH_A[@]}" "${JSON[@]}" -d '{"name":"general","group_type":"channel"}' | jq -r .group.id)
check "channels are open to the whole company" "false" "$(curl -sk "$API/channels" "${AUTH_B[@]}" | jq -r --arg c "$CHANNEL" '.channels[] | select(.id==$c) | .is_member')"
check "other companies cannot see the channel" "0" "$(curl -sk "$API/channels" "${AUTH_ADMIN[@]}" | jq -r --arg c "$CHANNEL" '[.channels[] | select(.id==$c)] | length')"
check "other companies cannot join it" "404" "$(status -X POST "$API/groups/$CHANNEL/join" "${AUTH_ADMIN[@]}")"
check "colleague joins a channel" "channel" "$(curl -sk -X POST "$API/groups/$CHANNEL/join" "${AUTH_B[@]}" | jq -r .group.category)"
check "private groups cannot be joined" "404" "$(status -X POST "$API/groups/$GROUP/join" "${AUTH_B[@]}")"
check "colleague leaves the channel" "true" "$(curl -sk -X POST "$API/groups/$CHANNEL/leave" "${AUTH_B[@]}" | jq -r .left)"

echo "== Files"
echo "smoke test file $RUN" >"$TMP_FILE"
FILE=$(curl -sk -X POST "$API/files/upload" "${AUTH_A[@]}" -F "file=@$TMP_FILE;filename=test.txt" | jq -r .file.id)
curl -sk -X POST "$API/messages" "${AUTH_A[@]}" "${JSON[@]}" \
  -d "{\"receiver_id\":\"$BOB\",\"content\":\"file\",\"message_type\":\"file\",\"file_id\":\"$FILE\"}" >/dev/null
check "recipient downloads attached file" "smoke test file $RUN" "$(curl -sk "$API/files/$FILE" "${AUTH_B[@]}")"
check "recipient cannot delete file" "403" "$(status -X DELETE "$API/files/$FILE" "${AUTH_B[@]}")"

echo "== Unread, mentions, threads, notes"
BODY="{\"group_id\":\"$GROUP\",\"content\":\"hey @bob$RUN please check\",\"message_type\":\"text\"}"
PARENT=$(curl -sk -X POST "$API/messages" "${AUTH_A[@]}" "${JSON[@]}" -d "$BODY")
PARENT_ID=$(jq -r .message.id <<<"$PARENT")
check "mention of a member is recognised" "bob$RUN" "$(jq -r '.message.mentions[0].username' <<<"$PARENT")"
GROUPS_B=$(curl -sk "$API/groups" "${AUTH_B[@]}")
check "group shows unread count" "1" "$(jq -r --arg g "$GROUP" '.groups[] | select(.id==$g) | .unread_count' <<<"$GROUPS_B")"
check "group shows unread mention" "1" "$(jq -r --arg g "$GROUP" '.groups[] | select(.id==$g) | .mention_count' <<<"$GROUPS_B")"
check "message is flagged unread for the reader" "true" "$(curl -sk "$API/messages/$GROUP" "${AUTH_B[@]}" | jq -r --arg m "$PARENT_ID" '.messages[] | select(.id==$m) | .unread')"
check "fetching messages does not mark them read" "1" "$(curl -sk "$API/groups" "${AUTH_B[@]}" | jq -r --arg g "$GROUP" '.groups[] | select(.id==$g) | .unread_count')"
check "acknowledging marks them read" "200" "$(status -X POST "$API/messages/$GROUP/read" "${AUTH_B[@]}" "${JSON[@]}" -d "{\"up_to\":\"$PARENT_ID\"}")"
check "unread clears after reading" "0" "$(curl -sk "$API/groups" "${AUTH_B[@]}" | jq -r --arg g "$GROUP" '.groups[] | select(.id==$g) | .unread_count')"
echo "thread attachment $RUN" >"$TMP_FILE"
TFILE=$(curl -sk -X POST "$API/files/upload" "${AUTH_B[@]}" -F "file=@$TMP_FILE;filename=spec.txt" | jq -r .file.id)
BODY="{\"group_id\":\"$GROUP\",\"parent_id\":\"$PARENT_ID\",\"content\":\"see section 2\",\"message_type\":\"file\",\"file_id\":\"$TFILE\"}"
REPLY=$(curl -sk -X POST "$API/messages" "${AUTH_B[@]}" "${JSON[@]}" -d "$BODY")
REPLY_ID=$(jq -r .message.id <<<"$REPLY")
check "thread reply with attachment and note" "see section 2|spec.txt" "$(jq -r '.message.content + "|" + .message.attachments[0].filename' <<<"$REPLY")"
check "replies stay out of the main chat" "0" "$(curl -sk "$API/messages/$GROUP" "${AUTH_A[@]}" | jq --arg r "$REPLY_ID" '[.messages[] | select(.id==$r)] | length')"
check "parent shows reply count" "1" "$(curl -sk "$API/messages/$GROUP" "${AUTH_A[@]}" | jq -r --arg m "$PARENT_ID" '.messages[] | select(.id==$m) | .reply_count')"
check "thread lists the reply" "see section 2" "$(curl -sk "$API/messages/$PARENT_ID/thread" "${AUTH_A[@]}" | jq -r '.replies[0].content')"
check "note on an attachment can be edited" "updated note" "$(curl -sk -X PUT "$API/messages/$REPLY_ID" "${AUTH_B[@]}" "${JSON[@]}" -d '{"content":"updated note"}' | jq -r .message.content)"
check "others cannot edit the note" "403" "$(status -X PUT "$API/messages/$REPLY_ID" "${AUTH_A[@]}" "${JSON[@]}" -d '{"content":"x"}')"
check "Vault details are not shown to users" "null" "$(curl -sk "$API/encryption/status" "${AUTH_A[@]}" | jq -r .vault)"

echo "== Tokens and WebSocket"
check "refresh token works" "true" "$(curl -sk -X POST "$API/auth/refresh" "${JSON[@]}" \
  -d "{\"refresh_token\":\"$REFRESH_A\"}" | jq '.token | length > 20')"
check "refresh token is single-use" "401" "$(status -X POST "$API/auth/refresh" "${JSON[@]}" -d "{\"refresh_token\":\"$REFRESH_A\"}")"
WS_HEADERS=(--http1.1 -m 3 -H "Connection: Upgrade" -H "Upgrade: websocket"
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==")
ticket() { curl -sk -X POST "$API/ws-ticket" "$@" | jq -r .ticket; }
TICKET=$(ticket "${AUTH_A[@]}")
check "websocket connects with a ticket" "101" "$(status "${WS_HEADERS[@]}" "$BASE/ws/chat/$ALICE?ticket=$TICKET")"
check "a ticket works only once" "401" "$(status "${WS_HEADERS[@]}" "$BASE/ws/chat/$ALICE?ticket=$TICKET")"
check "access tokens are not accepted in the URL" "401" "$(status "${WS_HEADERS[@]}" "$BASE/ws/chat/$ALICE?token=$TOKEN_A")"
check "websocket rejects another user's ticket" "403" "$(status "${WS_HEADERS[@]}" "$BASE/ws/chat/$BOB?ticket=$(ticket "${AUTH_A[@]}")")"

echo "== Forgot password (email via Mailpit)"
MAILPIT="${MAILPIT_URL:-http://localhost:8025}"
register carol "$(invite carol "${AUTH_A[@]}")" >/dev/null
BODY="{\"email\":\"carol$RUN@example.com\"}"
check "forgot password is accepted" "202" "$(status -X POST "$API/auth/forgot-password" "${JSON[@]}" -d "$BODY")"
check "unknown email gets the same answer" "202" "$(status -X POST "$API/auth/forgot-password" "${JSON[@]}" -d '{"email":"nobody-'$RUN'@example.com"}')"
RESET_TOKEN=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  MAIL_ID=$(curl -s "$MAILPIT/api/v1/search?query=to:carol$RUN@example.com%20subject:reset" | jq -r '.messages[0].ID // empty')
  [[ -n "$MAIL_ID" ]] && RESET_TOKEN=$(curl -s "$MAILPIT/api/v1/message/$MAIL_ID" | jq -r .Text | grep -o '#reset=[A-Za-z0-9_-]*' | head -1 | cut -d= -f2) && break
  sleep 1
done
check "reset email delivered with a link" "true" "$([[ ${#RESET_TOKEN} -gt 20 ]] && echo true || echo false)"
BODY="{\"token\":\"$RESET_TOKEN\",\"new_password\":\"brand-new-pass1\"}"
check "reset link sets a new password" "200" "$(status -X POST "$API/auth/reset-password" "${JSON[@]}" -d "$BODY")"
check "reset link works only once" "400" "$(status -X POST "$API/auth/reset-password" "${JSON[@]}" -d "$BODY")"
BODY="{\"email\":\"carol$RUN@example.com\",\"password\":\"password123\"}"
check "old password no longer works" "401" "$(status -X POST "$API/auth/login" "${JSON[@]}" -d "$BODY")"
BODY="{\"email\":\"carol$RUN@example.com\",\"password\":\"brand-new-pass1\"}"
check "new password works" "200" "$(status -X POST "$API/auth/login" "${JSON[@]}" -d "$BODY")"

echo "== Admin"
LOGIN_ADMIN=$LOGIN_ROOT
check "members cannot open the admin API" "403" "$(status "$API/admin/stats" "${AUTH_B[@]}")"
check "company admins open their own console" "false" "$(curl -sk "$API/admin/stats" "${AUTH_A[@]}" | jq -r .platform)"
check "admin sees statistics" "true" "$(curl -sk "$API/admin/stats" "${AUTH_ADMIN[@]}" | jq '.users > 0')"
check "admin finds users" "bob$RUN" "$(curl -sk "$API/admin/users?q=bob$RUN" "${AUTH_ADMIN[@]}" | jq -r '.users[0].username')"
check "keys are in persistent Vault storage" "true" "$(curl -sk "$API/platform/encryption/status" "${AUTH_ADMIN[@]}" | jq -r .vault.persistent)"

RESET=$(curl -sk -X POST "$API/admin/users/$BOB/reset-password" "${AUTH_ADMIN[@]}" "${JSON[@]}" -d '{}')
TEMP_PW=$(jq -r .temporary_password <<<"$RESET")
check "admin reset signs the user out" "401" "$(status "$API/groups" "${AUTH_B[@]}")"
BOB_LOGIN=$(curl -sk -X POST "$API/auth/login" "${JSON[@]}" -d "{\"email\":\"bob$RUN@example.com\",\"password\":\"$TEMP_PW\"}")
check "temporary password signs in with must_change_password" "true" "$(jq -r .user.must_change_password <<<"$BOB_LOGIN")"
AUTH_B=(-H "Authorization: Bearer $(jq -r .token <<<"$BOB_LOGIN")")
check "everything else is blocked until the password is changed" "password_change_required" "$(curl -sk "$API/groups" "${AUTH_B[@]}" | jq -r .code)"
check "including the WebSocket" "403" "$(status "${WS_HEADERS[@]}" -H "Authorization: Bearer $(jq -r .token <<<"$BOB_LOGIN")" "$BASE/ws/chat/$BOB")"
BODY="{\"old_password\":\"$TEMP_PW\",\"new_password\":\"bobs-own-pass1\"}"
CHANGED=$(curl -sk -X POST "$API/auth/change-password" "${AUTH_B[@]}" "${JSON[@]}" -d "$BODY")
AUTH_B=(-H "Authorization: Bearer $(jq -r .token <<<"$CHANGED")")
check "after changing it, the account works normally" "200" "$(status "$API/groups" "${AUTH_B[@]}")"

BODY="{\"group_id\":\"$GROUP\",\"content\":\"buy cheap pills $RUN\",\"message_type\":\"text\"}"
SPAM_ID=$(curl -sk -X POST "$API/messages" "${AUTH_A[@]}" "${JSON[@]}" -d "$BODY" | jq -r .message.id)
BODY="{\"message_id\":\"$SPAM_ID\",\"reason\":\"spam\",\"details\":\"advertising\"}"
REPORT_ID=$(curl -sk -X POST "$API/reports" "${AUTH_B[@]}" "${JSON[@]}" -d "$BODY" | jq -r .id)
check "user can report a message" "36" "${#REPORT_ID}"
check "same message cannot be reported twice" "409" "$(status -X POST "$API/reports" "${AUTH_B[@]}" "${JSON[@]}" -d "$BODY")"
check "admin sees the report with the decrypted message" "buy cheap pills $RUN" "$(curl -sk "$API/admin/reports" "${AUTH_ADMIN[@]}" | jq -r --arg r "$REPORT_ID" '.reports[] | select(.id==$r) | .message.content')"
BODY='{"status":"resolved","note":"spam","delete_message":true,"suspend_user":true}'
check "admin resolves: delete message + suspend sender" "message_deleted,user_suspended" "$(curl -sk -X PUT "$API/admin/reports/$REPORT_ID" "${AUTH_ADMIN[@]}" "${JSON[@]}" -d "$BODY" | jq -r .action_taken)"
check "suspended user is signed out" "401" "$(status "$API/groups" "${AUTH_A[@]}")"
BODY="{\"email\":\"alice$RUN@example.com\",\"password\":\"password123\"}"
check "suspended user cannot sign in" "403" "$(status -X POST "$API/auth/login" "${JSON[@]}" -d "$BODY")"
check "admin actions are in the audit log" "true" "$(curl -sk "$API/admin/audit" "${AUTH_ADMIN[@]}" | jq '[.entries[] | select(.resource_type=="abuse_report")] | length > 0')"
BODY='{"status":"active"}'
check "admin can reactivate the account" "active" "$(curl -sk -X PUT "$API/admin/users/$ALICE" "${AUTH_ADMIN[@]}" "${JSON[@]}" -d "$BODY" | jq -r .user.status)"
check "company admins cannot suspend their owner" "403" "$(status -X PUT "$API/admin/users/$ALICE" "${AUTH_B[@]}" "${JSON[@]}" -d '{"status":"suspended"}')"

echo "== Company suspension"
LOGIN_B2=$(login bob)
AUTH_B2=(-H "Authorization: Bearer $(jq -r .token <<<"$LOGIN_B2")")
check "suspending a company" "suspended" "$(curl -sk -X PUT "$API/platform/companies/$COMPANY_A" "${JSON[@]}" "${AUTH_ADMIN[@]}" -d '{"status":"suspended"}' | jq -r .company.status)"
check "signs out its members" "401" "$(status "$API/groups" "${AUTH_B2[@]}")"
BOB_LOGIN_BODY="{\"email\":\"bob$RUN@example.com\",\"password\":\"bobs-own-pass1\"}"
check "and blocks sign-in" "company_inactive" "$(curl -sk -X POST "$API/auth/login" "${JSON[@]}" -d "$BOB_LOGIN_BODY" | jq -r .code)"
curl -sk -X PUT "$API/platform/companies/$COMPANY_A" "${JSON[@]}" "${AUTH_ADMIN[@]}" -d '{"status":"active"}' >/dev/null
check "reactivated company can sign in again" "200" "$(status -X POST "$API/auth/login" "${JSON[@]}" -d "$BOB_LOGIN_BODY")"

echo
echo "Passed: $PASS  Failed: $FAIL"
[[ $FAIL -eq 0 ]]
