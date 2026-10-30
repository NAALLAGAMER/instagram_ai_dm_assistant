# Personal Instagram AI DM Assistant (human approval)

A small Python/Flask inbox for an Instagram **professional** account. It receives inbound DM webhook events, creates a bilingual Hindi/English suggested reply, and lets the account owner review/edit/approve each reply before sending.

## Safety and scope

- Uses Meta's official Instagram Messaging API only.
- Does not ask for or store your Instagram password.
- Does not scrape Instagram, automate browser login, or message people first.
- Only replies to a person who has messaged the professional account, subject to Meta's messaging rules and permissions.
- No reply is sent automatically. The dashboard requires a human click for every send.
- The built-in draft generator is a local keyword/intent-based helper, not a hosted large language model. Edit every suggestion before sending.
- Use only for an account you own or are authorized to manage.

## Requirements

- Python 3.10+
- A Meta developer app configured for Instagram Messaging.
- Instagram Business or Creator account and the current permissions required by Meta.
- Webhook callback reachable by Meta over HTTPS for real webhook delivery.
- `instagram_business_manage_messages` permission for the Instagram Login flow described in Meta's current collection. Your app may need review/roles for non-test users.
- A messaging recipient who has messaged your professional account first.

Meta's current Instagram Login collection documents the professional-account messaging flow, `instagram_business_manage_messages`, and sending through `POST https://graph.instagram.com/{version}/{ig_user_id}/messages`. See:
https://www.postman.com/meta/instagram/documentation/6yqw8pt/instagram-api

Meta's documentation and dashboard labels can change. Follow the current Meta app setup and webhook subscription screens; do not guess permissions if your app uses a different login path.

## Install

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
python make_password_hash.py
```

Paste the generated hash into `.env`. Set all Meta values in `.env`. Generate your own random `FLASK_SECRET_KEY` and `META_VERIFY_TOKEN`.

Do not put `.env` in a public repository. Do not send tokens or app secrets in chat.

## Meta setup checklist

1. Create/configure a Meta developer app and add the Instagram API / Messaging capability available for your account.
2. Connect your Instagram **professional** account and authorize the app with the required messaging permission. For the Instagram Login flow, the current Meta collection lists `instagram_business_basic` and `instagram_business_manage_messages`.
3. Set `IG_USER_ID` to the professional account's Instagram user ID and `IG_ACCESS_TOKEN` to its authorized access token.
4. Configure a webhook callback URL ending in `/webhook`, with the exact same `META_VERIFY_TOKEN` as in `.env`.
5. Subscribe to the Instagram `messages` webhook field in the Meta app dashboard. The exact object/field setup depends on the login product selected in Meta.
6. Set `META_APP_SECRET` to the app secret so incoming webhook signatures can be verified.
7. Test with an account permitted by your app's roles/test setup. For production access, complete Meta's app review and any required business verification.
8. Make sure the Instagram account has allowed connected tools/message access in its Instagram settings, if Meta's current setup requires it.

## Run

```bash
python app.py
```

Open http://127.0.0.1:5000/login and sign in using the dashboard username/password you configured.

The dashboard is intentionally bound to localhost by default. To receive real Meta webhooks, deploy behind HTTPS on a trusted host, set `HOST=127.0.0.1` behind a production WSGI server/reverse proxy, and point Meta to `https://YOUR-DOMAIN/webhook`. Do not expose Flask's development server directly to the internet.

## Workflow

1. A person sends a DM to the professional Instagram account.
2. Meta posts a signed webhook event to `/webhook`.
3. The app verifies `X-Hub-Signature-256`, deduplicates by message ID, and saves the inbound text to SQLite.
4. The app creates a Hindi/English draft.
5. The owner signs in, reviews and edits the draft, then clicks **Approve & send**.
6. The app sends the reply through the official API and records the result.

## Important platform limits

- The recipient must have messaged the professional account first; this app is not for cold DMs.
- Meta's messaging windows, policy requirements, app review, permissions, and recipient eligibility apply. The API can reject replies outside allowed windows.
- This starter supports text messages only. Attachments, story replies, handover, OAuth onboarding, and token refresh are not implemented.
- Use HTTPS and a production WSGI server for deployment. Back up the SQLite database securely.
