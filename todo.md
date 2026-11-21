# Group messaging TODO

## Client and server integration

### Client

- [ ] Run each client in its own Docker container on a shared network. Start a WebSocket listener and register the client’s user ID, reachable IP address, and port with the server. Refresh the address when it changes.
- [ ] Replace the hard-coded user list with the server’s user directory. Look up peer addresses there before opening direct WebSocket connections.
- [ ] Generate key packages locally, publish the signed public package at startup, and publish a fresh package after the current one is claimed. Keep private keys and group state on the client.
- [ ] Look up the invitee’s public key package when adding a member. Send signed Commits to existing members and the encrypted Welcome to the invitee over WebSocket.
- [ ] Encrypt each chat message locally, send it directly to the other group members over WebSocket, and upload one copy of the encrypted message to the server for the demo archive. Decrypt incoming messages locally before displaying them.

### Server

- [ ] Extend the FastAPI server with a user directory that lists registered users and stores each client’s current WebSocket IP address and port.
- [ ] Add endpoints for clients to publish and refresh their own signed public key packages and for inviters to claim an available package once.
- [ ] Store group IDs and names in a `groups` table. Store each encrypted chat message in a separate `messages` table linked to `groups` by `group_id`. Preserve the epoch, encrypted sender data, and ciphertext. Use Alembic and PostgreSQL for database integration.
- [ ] Update the message endpoint to accept encrypted records for the demo archive. Live delivery stays between clients over WebSocket.

### End-to-end demo

- [ ] Start the server and multiple client containers. Verify user discovery, invitations, direct encrypted messaging, and one archived record per message under the correct group. Remove a member and verify the remaining clients can still exchange messages.

## Original TODO List

### Remaining demo integration

Both changes belong in the `add()` helper in `Security/main.py`. The delivery methods already exist.

- [ ] Have the invitee publish its generated package using `publish_key_package()`. Have the inviter claim it with `fetch_key_package()` and pass the claimed package to `add_member()`.
- [ ] Send `result.welcome` to the invitee with `send_message()`. Drain the invitee’s inbox, confirm the received object is a `Welcome`, and pass that object to `accept_welcome()`.
- [ ] Calculate the ratchet interval in messages as `((ID1_last3 + ID2_last3 + ID3_last3) % 10) + 2`, using the last three digits of each of the three project members’ student IDs.
- [ ] Calculate the simulated group size as `4 + (group_registration_order % 3)` and configure the demo with that many client containers.
- [ ] Configure the demo to rotate the group keys after every calculated number of group chat messages. Send enough messages to show the rotation and verify that members can still exchange messages in the new epoch.
- [ ] Show both derivations in the report. Include the input values, the arithmetic, and the resulting ratchet interval and simulated group size.

### Optional message buffering

The demo delivers messages in order. Its receiver currently rejects an unexpected epoch or sender generation.

- [ ] Retain a future-epoch message until the corresponding Commit has been applied, or a later-generation message until the missing message from that sender has been processed. Retry through normal decryption and continue rejecting replays.

### Send and receive through the delivery service

- [x] Relay encrypted group messages to each intended recipient using `DeliveryService.send_message()`.
- [x] Include the group ID and current epoch so a recipient can select and check its local group state.
- [x] Retrieve queued messages with `receive_messages()` and pass application messages to `MessageService.decrypt()` with the recipient’s local state.
- [x] Allow users to publish public key packages and inviters to claim them through the relay.

### Process messages locally

- [x] Derive a fresh message key from the sender’s ratchet and use it to encrypt the text. Each sender’s chain starts from the epoch encryption secret.
- [x] Include the sender’s leaf index and generation with each message. The implementation encrypts these fields and exposes the epoch.
- [x] Check that the incoming group ID and epoch match the recipient’s local state.
- [x] Track the next expected generation for each sender, derive the matching decryption key, and advance the receive ratchet after successful verification.
- [ ] Hold early messages locally until the recipient catches up (optional).

### Use proposals and Commits

- [x] Represent one membership action per signed Commit using an Add or Remove proposal.
- [x] Stage the Add locally and send the Commit to the other existing members so each can apply the change.
- [ ] Deliver the Welcome to the invitee through the relay in the demo. The current demo passes it directly to `accept_welcome()`.

### Build and process the Welcome

- [x] Give the invitee the secret material needed to join the current epoch. The Welcome carries an encrypted epoch seed in place of the ancestor secret envisioned in the original checklist.
- [x] Include the ordered public leaves, parent public keys, and signing-key roster so the invitee can reconstruct the tree and identify member slots.

### Update existing members when a user joins

- [x] Include the committer’s updated public leaf key and ordered path nodes in the Add Commit.
- [x] Encrypt the appropriate path secret for each eligible existing recipient, including members in the opposite subtree.
- [x] Let each continuing member recover its path secret, derive the remaining keys on its path, and advance to the same epoch as the committer.
