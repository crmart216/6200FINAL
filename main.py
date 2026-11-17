from users import *
def main():
    alice0x1 = User("Alice Alexan")
    bob02x13 = User("Bob Bolard")
    charliXdx = User("Charli Cantenely")
    daniel = User("Daniel D")
    createAccountKeys(alice0x1)
    createAccountKeys(bob02x13)
    createAccountKeys(charliXdx)
    createAccountKeys(daniel)
    # issue: createAccountKeys(daniel)
    createGroup(alice0x1, "Epic Group Chat", bob02x13, charliXdx, daniel)
    alice0x1.treeNode.checkRoot()
  #  message = encryptMsg(1,3)
  #  print(message)
  #  message = decryptMsg(4,3)
  #  print(message)
if __name__ == "__main__":
    main()