import random
import os
from collections import deque
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hpke import Suite, KEM, KDF, AEAD
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from deliveryService import *

# Established la suite 
suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
# Derived from Lab 04
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2
# Setup for DH's exchanges from GeeksForGeeks
def power(a, b, p):
    if b == 1:
        return a
    else:
        return pow(a, b) % p
# Set up for Personal Nodes
class TreeNode:
    def __init__(self, name):
        self.name = name
        self.privateKey = None
        self.leaf_index = None
        self.admin = None
        self.pubKey = None
        self.parent = None
        self.left = None
        self.right = None
        self.side = None
        self.epoch = None
        self.nextKey = None
        self.rootKey = None
    def keyGenerating(self,key):
        salt = None
        info = b"keyGeneration"
        hkdf = HKDF(
        algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            info=info,
    )
        fullkey = hkdf.derive(key)
        return fullkey
    def checkRoot(self):
        print(self.rootKey)
    def leafStatus(currentNode):
        return currentNode != None and currentNode.left is None and currentNode.right is None
root = TreeNode('Root Key')
admin_Group = None
# Private Key generator
def genPrivK():
    return x25519.X25519PrivateKey.generate()
#Function to create public keys
def gen_DHpub(privK):
   return privK.public_key()
# Initialize a user and create 3 initial keys
class User:
    def __init__(self,name):
        self.name = name
        self.privateKey = None
        self.pubKey = None
        # Private database for each user for their initial keys
        self.PrivForPackage = []
        # Public database sent to the delivery service (DS) that any user can pull
        self.pubPackage = []
        # Creates DS_View of person I think
        self.dsAccount = DS_User(name)
        self.treeNode = None
        self.sendCounter = 1
        self.recieveCounter = 1
# adding a new member to the users individual tree
    def addNewMember(self,newMember):
        if(root.right is None):
            root.right = TreeNode(newMember.name)
            root.right.pubKey = newMember.dsAccount.dsPublic[0].startingKey
            root.right.parent = root
            print("Adding:", newMember.name)
            root.right.parent.leaf_index = 2
            return root.right
        queue = deque([root])
        while queue:
            tempNode = queue.popleft()
        # checks if the left node is a leaf node and if it is then a new node needs to be made to combine the two then calc the root
            if tempNode.left and tempNode.left.left is None and tempNode.left.right is None:
                old_Leaf = tempNode.left
                newInterMed = TreeNode("Upper Node Left")
                newInterMed.left = old_Leaf
                newInterMed.right = TreeNode(newMember.name)
                newInterMed.right.pubKey = newMember.dsAccount.dsPublic[0].startingKey
                old_Leaf.parent = newInterMed
                newInterMed.right.parent = newInterMed
                tempNode.left = newInterMed
                newInterMed.parent = tempNode
                return newInterMed.right
            elif tempNode.left:
                queue.append(tempNode.left)
            if tempNode.right and tempNode.right.left is None and tempNode.right.right is None:
                old_Leaf = tempNode.right
                newInterMed = TreeNode("Upper Node Right")
                newInterMed.left = old_Leaf
                newInterMed.right = TreeNode(newMember.name)
                newInterMed.right.pubKey = newMember.dsAccount.dsPublic[0].startingKey
                newInterMed.right.parent = newInterMed
                old_Leaf.parent = newInterMed
                tempNode.right = newInterMed
                newInterMed.parent = tempNode
                return newInterMed.right
            elif tempNode.right:
                queue.append(tempNode.right)
        # If all else fails
        return None
    # MISSING: NEEDS TO SEND OUT PRIVATE MESSAGES TO THE RIGHT USERS
    def generateRootKey(self,useKey):
        current = self.treeNode
        print(current.name, "starting key is:", useKey)
        while current.parent != root:
            # LEFT SIDE OF TREE
            if current.parent.left is current:
                current.parent.nextKey = current.keyGenerating(useKey)
                # Checks if parent node has a right child
                if current.parent.right is None:
                    print("No right side to share with")
                    print("root key before:", useKey)
                    print("root key after:", current.parent.nextKey)
                else:
                    print("The key found at: ", current.parent.name)
                    # Need to add a while loop to check for children and how many to share with
                    print("Need to share with:", current.parent.right.name)
                    # Will encrypt a message specifically for the parent 
                    cipher = suite.encrypt(current.parent.nextKey, current.parent.right.pubKey, info=b"Key Update")
                    print("Sending:",cipher, "to user:", current.parent.right.name)        
            elif current.parent.right is current: 
                current.parent.nextKey = current.keyGenerating(useKey)
                if current.parent.left is None:
                    print("No left side to share with")
                    print("root key before:", useKey)
                    print("root key after:", current.parent.nextKey)
                else:
                    print("The key found at: ", current.parent.name)
                    print("Need to share with:", current.parent.left.name)
                    cipher = suite.encrypt(current.parent.nextKey, current.parent.left.pubKey, info=b"Key Update")
                    print("Sending:",cipher, "to user:", current.parent.left.name)           
            useKey = current.parent.nextKey
            current = current.parent
        if current.parent == root:
                current.rootKey = current.keyGenerating(useKey)
                print("new root key is: ", current.rootKey)
                if current.parent.left != current and current.parent.left != None:
                    print("need to share with: ", current.parent.left.name)
                    leftSide = current.parent.left
                    queue = deque([leftSide])
                    while queue:
                        tempNode = queue.popleft()
                    if tempNode.leafStatus():
                        print("need to share with: ", tempNode.name)
                        cipher = suite.encrypt(current.rootKey, tempNode.pubKey, info=b"Key Update")
                        print("Sending:",cipher, "to user:", tempNode.name) 
                    else: 
                        if tempNode.left != None:
                            queue.append(tempNode.left)
                        if tempNode.right != None:
                            queue.append(tempNode.right)
                if current.parent.right != current and current.parent.right != None:
                    rightSide = current.parent.right
                    queue = deque([rightSide])
                    while queue:
                        tempNode = queue.popleft()
                        if tempNode.leafStatus():
                           print("need to share with: ", tempNode.name)
                           cipher = suite.encrypt(current.rootKey, tempNode.pubKey, info=b"Key Update")
                           print("Sending:",cipher, "to user:", tempNode.name) 
                        else: 
                            if tempNode.left != None:
                                queue.append(tempNode.left)
                            if tempNode.right != None:
                                queue.append(tempNode.right)
                    
                return current.rootKey
    def keyRatcheting(self,key):
                salt = None
                info = b"keyGeneration"
                hkdf = HKDF(
                algorithm=hashes.SHA256(),
                    length=48,
                    salt=salt,
                    info=info,
            )
                fullkey = hkdf.derive(key)
                self.nextKey = fullkey[16:]
                return fullkey[:16]
    # Encryption and Decryption functions
    def encryptMsg(self,message,key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        newKey = self.keyRatcheting(key)
        aesgcm = AESGCM(newKey)
        nonce = self.sendCounter.to_bytes(12, byteorder='big')
        self.sendCounter += 1
        ciphertext = aesgcm.encrypt(nonce,message,b"") 
        return ciphertext, nonce
    def decryptMsg(self,cipherText,key,nonce_sent):
        newKey = self.keyRatcheting(key)
        aesgcm = AESGCM(newKey)
        nonce_sent = self.recieveCounter.to_bytes(12, byteorder='big')
        self.recieveCounter += 1
        decrypted = aesgcm.decrypt(nonce_sent,cipherText,b"")
        return decrypted.decode('utf-8')
            
class keyPackage:
    def __init__(self, number, name):
        self.number = number
        self.initKey = None
        self.startingKey = None
        self.signatureKey = None
        self.signedPackage = None
        self.cred = name
    # Serializing key Package to be signed: Used Gemini to help understand the structure of this function
    def serialize_Package(self) -> bytes:
        initPubKey_bytes = self.initKey.public_bytes_raw()
        startPubKey_bytes = self.startingKey.public_bytes_raw()
        sig_bytes = self.signatureKey.public_bytes_raw()
        cred_bytes = self.cred.encode("utf-8")
        finalPiece = initPubKey_bytes + startPubKey_bytes + sig_bytes + cred_bytes
        return finalPiece
# MLS Documentation for updating a Group Chat (whether it be starting one or updating one)
#A _Proposal_ message proposes a change to be made in the next epoch, such as adding or removing a member.
class Proposal:
    def __init__(self, action):
        self.action = action
        self.epoch = Epoch
        print("New Proposal: ", action)
#A _Commit_ message initiates a new epoch by instructing members of the group to implement a collection of proposals.
class Commit:
    def __init__(self, *actions):
        self.plan = [*actions]
        self.currentEpoch = Epoch
        self.nextEpoch = self.currentEpoch
        self.nextEpoch +=1
class welcomeMsg:
    def __init__(self,epoch,tree_position, rootKey):
        self.epoch = epoch 
        self.node= tree_position
        self.rootKey = rootKey      
# Creating initial keys for creating a new group chat
# Generated priv sits in a database only accessed by the User themselves
# Generated pub sits in a database sent to the Delivery Service (OpenMLS documentation)
def init_KeyGen(user,amount):
    i = 0
    start=0
    while i < amount:
        start+=1
        storedUserKeys = keyPackage(start,"Package:")
        # generating private keys for initial key(the welcome message key) and Chat Private(the private chat key)
        initPriv = genPrivK()
        chatPriv = genPrivK()
        # generating private Key signature: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
        signaturePriv = ed25519.Ed25519PrivateKey.generate()
        # storing the private keys for the User not in the DS!
        storedUserKeys.initKey = initPriv
        storedUserKeys.startingKey = chatPriv
        storedUserKeys.signatureKey = signaturePriv
        user.PrivForPackage.append(storedUserKeys)
        # Now creating the Public Portion of this package
        storedDSKeys = keyPackage(start,"Public Package")
        generated_initPub = gen_DHpub(initPriv)
        generated_ChatPub = gen_DHpub(chatPriv)
        signaturePub = signaturePriv.public_key()
        storedDSKeys.initKey = generated_initPub
        storedDSKeys.startingKey = generated_ChatPub
        storedDSKeys.signatureKey = signaturePub
        # Signing the package
        preparedDs = storedDSKeys.serialize_Package()
        packageSigned = signaturePriv.sign(preparedDs)
        storedDSKeys.signedPackage = packageSigned
        user.pubPackage.append(storedDSKeys)
        # Add delivery service to update its pubKey database
        user.dsAccount.dsPublic.append(storedDSKeys)
        i += 1
        
## Creating an account which calls init_KeyGen
def createAccountKeys(user):
    print("Generating Keys for User: ", user.name)
    init_KeyGen(user,3)
# Generate a new key once one has been used
def newInitKeys(user):
    user.PrivForPackage.pop(0)
    user.pubPackage.pop(0)
    # Remove Keys on Public Database too
    user.dsAccount.dsPublic.pop(0)
    init_KeyGen(user,1)
# ----- Create a group chat -----
# "When client A wants to establish a group with clients B and
# C, it first initializes a group state containing only itself and
# downloads KeyPackages for B and C" https://datatracker.ietf.org/doc/rfc9420/.
def createGroup(creator,title, *initialMembers):
    # Setting the Creator to admin status (giving them the option of adding and removal)
    global Epoch
    Epoch = 0
    adminNode = TreeNode(creator.name)
    adminNode.admin = True
    adminNode.privateKey = genPrivK()
    adminNode.pubKey = gen_DHpub(adminNode.privateKey)
    adminNode.parent = root
    creator.treeNode = adminNode
    root.left = adminNode
    creator.treeNode.rootKey = adminNode.keyGenerating(adminNode.privateKey.private_bytes_raw())
   # print("New Group Chat:", title, "| Admin:", creator.name)
   # print("Creator Private Key: ", adminNode.privateKey.private_bytes_raw().hex(), "Root Key: ", creator.treeNode.rootKey.hex())
    # Creating the Proposal and Commits
    # add person will be its own function
    # Testing varying amount of parameters
    for members in initialMembers:
        try:
            members.dsAccount.dsPublic[0].signatureKey.verify(members.dsAccount.dsPublic[0].signedPackage,members.dsAccount.dsPublic[0].serialize_Package())
            print(members.name)
            newNodePosition = creator.addNewMember(members)
            # Welcome should send the Epoch they will be at, an ordered array of members so each can be added per user
            # What i mean is alice and bob are in a group chat, want to add charli, alice provides charli with the array [alice,charli] so charli can know the exact positions of each
            newWelcome = welcomeMsg(Epoch,newNodePosition,creator.treeNode.rootKey)
            createChat = Proposal("addNewMember(adminNode,members)")
            newKey = genPrivK()
            useKey = newKey.private_bytes_raw()
            creator.treeNode.rootKey = creator.generateRootKey(useKey)
            print(creator.treeNode.rootKey)
        except InvalidSignature:
            return False



