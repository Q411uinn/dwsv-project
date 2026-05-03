import dns.resolver

def query_txt(domain, server='127.0.0.1'):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server]
    try:
        answer = resolver.resolve(domain, 'TXT')
        return [r.to_text() for r in answer]
    except Exception as e:
        print(f"DNS query failed: {e}")
        return []

def query_proof(subdomain):
    domain = f"{subdomain}.example.com"
    txt = query_txt(domain)
    if not txt:
        return None
    txt = txt[0].strip('"')
    if "proof=" in txt:
        proof_str = txt.split("proof=")[1]
        items = proof_str.split(",")
        proof = []
        for item in items:
            direction, h = item.split(":")
            proof.append((int(direction), h.strip()))
        return proof
    return None
