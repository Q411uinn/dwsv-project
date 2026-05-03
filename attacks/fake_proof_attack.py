import random
from dns_module.dns_query import query_txt,query_proof
from merkle.merkle_tree import verify_proof, hash_leaf, hash_node

def random_hash():
    return hash_node(str(random.random()), str(random.random()))

def generate_fake_proof(depth=3):
    proof = []
    for _ in range(depth):
        direction = random.choice([0,1])
        proof.append((direction, random_hash()))
    return proof

def extract_root(txt_record):
    txt = txt_record[0].strip('"')
    parts = txt.split(";")
    for p in parts:
        if "c=" in p:
            return p.split("=")[1].strip()
    return None

def reuse_proof_attack():
    target = "evil"
    txt = query_txt("_auth.example.com")
    root = extract_root(txt)

    # 拿合法 proof
    legit_proof = query_proof("www")

    print(f"\n[+] Reuse proof attack (using www proof for evil)")

    result = verify_proof(target, legit_proof, root)

    print(f"[!] Verification result: {result} (应该是 False)")
    
def main():
    target = "evil"
    txt = query_txt("_auth.example.com")
    root = extract_root(txt)
    fake_proof = generate_fake_proof()
    print(f"[+] Target: {target}")
    print(f"[+] Fake proof: {fake_proof}")
    result = verify_proof(target, fake_proof, root)
    print(f"[!] Verification result: {result} ")
    #result1= reuse_proof_attack()
    #print(f"reuse_proof_attack result: {result1}")
    
if __name__ == "__main__":
    main()
