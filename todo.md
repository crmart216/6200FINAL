# Todo list for code

### Need to add a send and receive message function in delivery service

- Delivery service is the relay for messages
- A user sends a encrypted message over the delivery service to the group chat
- The user will send an encrypted message and it will also contain public information like the current epoch and the possible sender state, allowing for users to make sure they are on the right update
- Receive needs to receive the message, and pass it back to the users local state (user.py) where it can be processed
- Users need to be able to upload their public packages to the delivery server (i have a code which adds it so i think thats done)

### User local processing of message (send/receive)

- User needs to encrypt their message with the root key that has been ratcheting however many times
- User needs to also include the current epoch AND along with sender state (unencrypted, its public so yuh)
- For receiving message user needs to take in the epoch current ensure that they are in sync first!
  - if not user should locally store it for later use (this is lowkey not rly important for our project as hopefully everything should be sent in order)
- But if in order, user ratchets so the nextkey to match that change in root key that the sender had made: should then have matching dec key to the sender encrypted so user can decrypt the message. User must always have a count of the sender state

### Need to fix the add new user function to allow for a 4th member to be added

- I (Zaeya) can do this i just need to remember what needed to be fixed lol

### Need to actually utilize the proposal and commit functions

- Right now the proposal is shown but not used, we honestly might just need a commit and can just have only one action occur at a time
- But commit should actually should send out the needed message to the right users
  - Such as welcome message: sends it to the new user allowing for them to have created treeNodes yay
  - Sends out messages to the existing members upon a new member entry so every user can adjust their tree accordingly.
    - the add new member function is already localized

### Need to work on the welcome message

- Talked about it above but it needs to give the new user everything they need
- supposed to give the new user the least highest node needed find the root key
- say alice and charli(new user) are the child of a upper node (not root)
  - alice needs to only send charli the ratcheted key at upper node and then all alice has to do is generate another ratchet to get the root key if its the upper node parent
- it also provides charli with the current tree structure in some way so charli can reconstruct the whole tree
  - included in this is the public keys of all users to allow for sending specific messages(more on this below

### Within adding a new member message to existing members

- Alice adds charli to the group
- alice finds the new root key yea? Well alice needs to tell the existing members the information they need. If charli is on the same side as alice charli needs to know the node they share in some way so she can ratchet up however many times after(what i just said above)
- if bob is on the right side alice needs to tell him what the new root key is since bob doesnt have access to the left sides upper node content.
