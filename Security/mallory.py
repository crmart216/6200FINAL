# Attacker class that poses as a network sniffer collecting the encrypted messages for later use
# Mallory steals the state of a user which contains the neeeded information to decrypt messages.
class MallorySniff:
    def __init__(self):
        self.loggedTraffic = []
        
    def attackerDecrypt(self, service,stolen_state):
        attacker_state = stolen_state
        for packet in self.loggedTraffic:
            try:
                plaintext = service.decrypt(attacker_state, packet)
                print(f"[MALLORY] decrypted successfully: {plaintext}")
            except Exception as err:
                print(f"[MALLORY] Failed on Message: {err}")   