import time
from dns_module.dns_query import query_txt, query_proof
from merkle.merkle_tree import verify_proof

def measure():
    # root 查询
    t1 = time.time()
    query_txt("_auth.example.com")
    t2 = time.time()

    # proof 查询
    query_proof("www")
    t3 = time.time()

    # verify
    verify_proof("www", query_proof("www"), "dummy")
    t4 = time.time()

    print("DNS root 查询:", t2 - t1)
    print("DNS proof 查询:", t3 - t2)
    print("Merkle 验证:", t4 - t3)

if __name__ == "__main__":
    measure()

