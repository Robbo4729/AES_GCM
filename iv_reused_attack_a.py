# author: linzheng tan
# Demo: IV Reuse Attack (Keystream Reuse / Known-Plaintext Attack)
# Scenario: Alice-Bank communication. Attacker knows one plaintext (e.g., a common header or query).

from gcm import aes_gcm_encrypt
from gcm_auxiliary import (
    hex_to_list, list_to_hex, string_to_list, 
    list_to_string, xor_bytes
)

def iv_reused_attack_a():
    # --- SETUP: Bank System Simulation ---
    # Shared secret key and a reuse IV
    key = hex_to_list("feffe9928665731c6d6a8f9467308308")  
    reused_iv = hex_to_list("cafebabefacedbaddecaf888")    
    
    # AAD is present in the protocol, but IRRELEVANT for confidentiality attack
    aad = string_to_list("BankProtocol:v1") 

    print("--- STEP 1: Attacker intercepts two messages with the same IV ---")
    
    # Message 1: The "Known Plaintext"
    # This is a predictable message, e.g., a periodic heartbeat or balance check
    p1_str = "Balance Query..." 
    p1 = string_to_list(p1_str)
    c1, _ = aes_gcm_encrypt(p1, key, reused_iv, aad)
    
    # Message 2: The "Target Secret Message"
    # This is what the attacker wants to read
    p2_str = "Pay David $10000" 
    p2 = string_to_list(p2_str)
    c2, _ = aes_gcm_encrypt(p2, key, reused_iv, aad)

    print(f"[*] Intercepted Msg 1 (Known):   '{p1_str}'")
    print(f"[*] Intercepted Ciphertext 1:    {list_to_hex(c1)}")
    print(f"[*] Intercepted Ciphertext 2:    {list_to_hex(c2)}")
    
    print("\n--- STEP 2: Extracting Keystream ---")
    # Principle: C1 = P1 XOR Keystream
    # Therefore: Keystream = C1 XOR P1
    
    keystream = xor_bytes(c1, p1)
    print(f"[*] Recovered Keystream:         {list_to_hex(keystream)}")

    print("\n--- STEP 3: Decrypting Target Message ---")
    # Principle: P2 = C2 XOR Keystream
    # Limitation: Can only decrypt up to the length of the known keystream
    
    # Truncate ciphertext 2 if it's longer than our recovered keystream
    decryption_len = min(len(c2), len(keystream))
    
    recovered_p2 = xor_bytes(c2[:decryption_len], keystream[:decryption_len])
    recovered_p2_str = list_to_string(recovered_p2)
    
    print(f"[*] Decrypted Plaintext:         '{recovered_p2_str}'")
    
    print("\n--- STEP 4: Verification ---")
    if recovered_p2_str == p2_str:
        print("[SUCCESS] Secret message recovered successfully!")
    else:
        print("[FAIL] Recovery failed.")
        
    print("\n[NOTE] AAD was present but ignored. It only affects the Tag, not the Keystream.")

if __name__ == "__main__":
    iv_reused_attack_a()
