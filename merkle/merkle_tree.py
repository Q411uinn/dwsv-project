import hashlib

def hash_leaf(data):
    return hashlib.sha256(data.encode()).hexdigest()

def hash_node(left, right):
    return hashlib.sha256((left + right).encode()).hexdigest()

class MerkleTree:
    def __init__(self, leaves):
        self.raw_leaves = leaves
        self.leaves = [hash_leaf(leaf) for leaf in leaves]
        self.levels = []
        self.build_tree()

    def build_tree(self):
        nodes = self.leaves[:]
        self.levels.append(nodes)

        while len(nodes) > 1:
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1])

            parents = []
            for i in range(0, len(nodes), 2):
                parents.append(hash_node(nodes[i], nodes[i+1]))
            self.levels.append(parents)
            nodes = parents

    def get_root(self):
        return self.levels[-1][0]

    def get_proof(self, index):
        proof = []
        for level in self.levels[:-1]:
            if index % 2 == 0:
                sibling = level[index + 1] if index + 1 < len(level) else level[index]
                proof.append((1, sibling))
            else:
                sibling = level[index - 1]
                proof.append((0, sibling))
            index //= 2
        return proof

def verify_proof(leaf, proof, root):
    current = hash_leaf(leaf)
    for direction, sibling in proof:
        if direction == 0:
            current = hash_node(sibling, current)
        else:
            current = hash_node(current, sibling)
    return current == root

if __name__ == "__main__":
    subs = ["www", "api", "mail", "internal"]
    tree = MerkleTree(subs)
    print("✅ Merkle Root:", tree.get_root())
    for i, sub in enumerate(subs):
        print(f"{sub} proof:", tree.get_proof(i))
