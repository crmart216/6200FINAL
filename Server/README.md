# 6200 Group Chat API

Run these fish commands from the directory containing Server/ and Security/. Use
Docker Engine with the Compose v2 plugin. The API publishes port 8000. PostgreSQL
uses db:5432 inside Compose, so your host PostgreSQL ports 5432 and 5433 stay available.

## Configure

    umask 077
    cp -n .env.example .env

Edit .env locally. Generate a separate value for each password and API token with
`openssl rand -hex 32`. Set Alice's signing_public_key_b64 to the standard Base64
encoding of her client's raw 32-byte Ed25519 public key. Add one JSON record per
identity. Compose constructs SERVER_DATABASE_URL from the hexadecimal app password.
Shell variables override .env. Run from a fresh shell if host-run demo settings are exported.

## Start and inspect

    docker compose config --quiet
    docker compose up --build -d
    docker compose ps -a
    docker compose logs migrate
    docker compose exec -T api python -m alembic -c Server/alembic.ini current
    curl --retry 20 --retry-connrefused -fsS -o /dev/null -w 'Swagger HTTP %{http_code}\n' http://127.0.0.1:8000/docs
    curl -fsS http://127.0.0.1:8000/openapi.json

On a fresh project volume the PostgreSQL image runs Server/init-demo.sql once.
The script creates chat_demo_app and its database chat_demo. Alembic connects
as chat_demo_app after the database is healthy. The API starts after migration
exits with status 0. Expect revision 0001_initial_schema (head).
Use `docker compose logs db migrate api` for startup diagnostics.

## Authorize and register

Open http://127.0.0.1:8000/docs. Choose Authorize and enter Alice's raw API token.
Under Users, execute PUT /api/users/{user_id} with alice and the registration
example. Replace the listener URL with Alice's reachable address for peer discovery.
Execute GET /api/users and check the saved entry. The equivalent fish commands are:

    read -s -P 'Alice API token: ' token
    set api http://127.0.0.1:8000
    curl -fsS -X PUT "$api/api/users/alice" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"display_name":"Alice","websocket_url":"ws://alice.local:5555"}'
    curl -fsS "$api/api/users" -H "Authorization: Bearer $token"

For package publication, use the registered client's signed package. In the
client's Python session, with its configured test identity available as alice:

    from Security.services.group_services.key_services.key_package_service import KeyPackageService
    from Server.schemas.public_key_package import PublicKeyPackagePayload
    package, = KeyPackageService().generate_packages(alice, alice.user_id.encode("utf-8"), 1)
    print(PublicKeyPackagePayload.model_validate(package, from_attributes=True).model_dump_json())

Paste that JSON into the publish operation and copy its package_id into the path.
Keep the client identity and matching private package for Welcome processing.

## Restart and confirm persistence

    docker compose down
    docker compose up -d
    curl --retry 20 --retry-connrefused -fsS "$api/api/users" -H "Authorization: Bearer $token"
    set -e token
    docker compose down

Use the same Compose project name and .env each time. Ordinary down preserves
the named volume. Database passwords are initialized on first startup. To rotate
one on an existing volume, update the PostgreSQL role and matching local setting.
