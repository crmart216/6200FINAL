# 6200 Group Chat API

Run the commands from the project root with Docker Compose v2. The API publishes
port 8000. PostgreSQL stays on the Compose network at `db:5432`.

## Configure and deploy

Copy `.env.example` to `.env` for a fresh installation. Generate separate
hexadecimal passwords with `openssl rand -hex 32`. Keep existing database
passwords when reusing a volume. Keep `SERVER_PUBLIC_SIGNUP_ENABLED=false`
through deployment of the invitation API.

For an existing deployment, first put the legacy identities in
`SERVER_DEMO_IDENTITIES` in the local `.env`. Each JSON record has `user_id`,
the original `api_token`, and `signing_public_key_b64` for that account.
Use an empty array on a fresh deployment.

Apply the schema revision, backfill the existing credentials, then start the
API with database authentication. Use `sudo` for Docker commands if required.

    docker compose config --quiet
    docker compose up -d --wait db
    docker compose build api
    docker compose run --rm --no-deps migrate
    docker compose run --rm --no-deps --user=(id -u):(id -g) --volume "$PWD/Server/tools:/app/Server/tools:ro" api python -m Server.tools.backfill_api_credentials

Check the backfill's inserted, unchanged, and skipped counts before proceeding.
The command lists each skipped user ID without printing credentials. A skipped
identity has no existing account row. With signup disabled, that
identity cannot sign in or create an account through the API. Reconcile the
expected list of accounts before deployment. A key or credential conflict
rolls back the backfill. After the backfill succeeds, remove the legacy
identity JSON from `.env`. PostgreSQL now holds the credential digests.

    docker compose up -d
    docker compose ps -a
    docker compose logs --tail=30 db migrate api
    curl -fsS http://127.0.0.1:8000/openapi.json

On a fresh volume the database service runs `Server/init-demo.sql`. The
migration service applies Alembic through `0002_registration_invites`.
Open http://127.0.0.1:8000/docs and enter an issued or backfilled token under
**Authorize**. `PUT /api/users/{user_id}` updates an existing profile.
`GET /api/users` includes registered peer signing keys.

## Open signup after deploying invitations

Start the new image with signup disabled, then check the running API's OpenAPI
document. The `POST /api/users/{user_id}/key-packages/claims` operation should be
absent and the five invitation operations should be present.

    docker compose up --build -d api
    curl -fsS http://127.0.0.1:8000/openapi.json | python -c 'import json,sys; paths=json.load(sys.stdin)["paths"]; assert "post" not in paths.get("/api/users/{user_id}/key-packages/claims", {}); assert "post" in paths["/api/invitations/{invitation_id}/claim"]'

Then set `SERVER_PUBLIC_SIGNUP_ENABLED=true` in `.env` and recreate the API with
`docker compose up -d api`. The flag defaults to false. Use HTTPS for signup and
bearer-token requests.

## Invite a member

1. The founder sends `POST /api/groups/{group_id}/invitations` with
   `{"invitee_user_id": "bob"}`. Equivalent retries return the active invitation.
2. Bob polls `GET /api/invitations?direction=incoming&status=pending`. He sends
   `PUT /api/invitations/{invitation_id}/decision` with `{"decision": "decline"}`
   or with `"decision": "accept"` and a fresh signed `key_package`.
3. The founder polls outgoing `accepted` and `claimed` invitations separately,
   then calls `POST /api/invitations/{invitation_id}/claim`. Retries return the
   same package. Clients exchange their signed Commit and encrypted Welcome.
4. The founder publishes the full roster using
   `PUT /api/groups/{group_id}/epochs/{epoch}` with `invitation_id` and
   `member_user_ids`. Each epoch can add one invited member. The server commits
   the roster and marks the invitation completed in the same transaction.
   Retry with the same invitation ID and roster. Rotations and removals
   require only the roster.

A founder can create 20 new invitations per rolling minute across all groups.
Equivalent retries do not use that quota. Pending and accepted invitations
expire after 24 hours. Claimed invitations remain resumable past that deadline.
A package bound to an expired invitation stays reserved to that invitation.
Legacy package-claim records remain in PostgreSQL.

## Registration protocol

A challenge expires after five minutes. Sign a concatenation of
four-byte unsigned big-endian length-prefixed fields in this order:

1. UTF-8 string `6200 registration v1`
2. Canonical lowercase hyphenated challenge UUID text in UTF-8
3. Raw nonce bytes decoded from `challenge_b64`
4. User ID in UTF-8, using the submitted spelling and whitespace
5. Display name in UTF-8, with surrounding whitespace stripped
6. WebSocket URL in UTF-8, using the submitted text
7. Raw 32-byte Ed25519 public key

Send canonical standard Base64 for the public key and the 64-byte Ed25519
signature, including padding. User IDs and display names can contain up to
255 characters and exclude NUL. The listener URL can contain up to 2048
characters and excludes whitespace and ASCII controls. Preserve the exact
issued bearer token. The database digest is SHA-256 of that token's UTF-8
bytes without trimming.

The single-worker API tracks rate limits in memory using the TCP peer
address. Compose disables proxy header processing, so forwarded headers
cannot change the limiter key. The limits are 20 challenge requests and 10
registration requests per peer per 60-second window. Each endpoint keeps
at most 4096 active peer windows. At capacity, new peers wait for a window
to expire. Clients reaching the API through a shared proxy share its limit.

Run the cleanup command periodically to remove expired challenges:

    docker compose run --rm --no-deps --user=(id -u):(id -g) --volume "$PWD/Server/tools:/app/Server/tools:ro" api python -m Server.tools.prune_registration_challenges

Run the full test suite with `python -m Server.tools.run_tests --sudo`, or
omit `--sudo` if your user can access Docker directly. The runner uses the
isolated test database for signup, backfill, and concurrency checks.
