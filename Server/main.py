from fastapi import FastAPI

from .routes.router import router

app = FastAPI(
    title="6200 Group Chat API",
    description=(
        "Register peer WebSocket listeners, approve group invitations, "
        "publish group rosters, and archive encrypted messages. Use Authorize with "
        "your configured API token. Peers handle live delivery and decryption."
    ),
    openapi_tags=[
        {"name": "Users", "description": "Peer discovery and one-time public key packages."},
        {"name": "Invitations", "description": "Approve and claim signed packages for group membership."},
        {"name": "Groups", "description": "Group registration and founder-published epoch rosters."},
        {"name": "Messages", "description": "Ciphertext storage and membership-scoped transcripts."},
    ],
)
app.include_router(router)
