"""
merkle/merkle_tree.py  —  DWSV 方案 Merkle 树核心实现

改动说明（相比原版）：
1. hash_leaf 加 "leaf:" 域前缀，防止叶节点与内部节点哈希混淆攻击
2. get_proof 方向定义统一：direction=0 兄弟在左，direction=1 兄弟在右
3. verify_proof 与 get_proof 方向约定完全对应，修复原版方向不一致的 bug
"""
import hashlib


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def hash_leaf(data: str) -> str:
    return _sha256("leaf:" + data)


def hash_node(left: str, right: str) -> str:
    return _sha256(left + right)


class MerkleTree:
    def __init__(self, leaves: list):
        if not leaves:
            raise ValueError("子域集合不能为空")
        self.raw_leaves = leaves
        self.leaves = [hash_leaf(leaf) for leaf in leaves]
        self.levels = []
        self._build()

    def _build(self):
        nodes = self.leaves[:]
        self.levels = [nodes[:]]
        while len(nodes) > 1:
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1])
            parents = [
                hash_node(nodes[i], nodes[i + 1])
                for i in range(0, len(nodes), 2)
            ]
            self.levels.append(parents)
            nodes = parents

    def get_root(self) -> str:
        return self.levels[-1][0]

    def get_proof(self, index: int) -> list:
        """
        返回路径证明，每项为 (direction, sibling_hash)。
        direction=0: 兄弟在左（current 在右）
        direction=1: 兄弟在右（current 在左）
        """
        proof = []
        for level in self.levels[:-1]:
            padded = level[:]
            if len(padded) % 2 != 0:
                padded.append(padded[-1])
            if index % 2 == 0:
                sibling_idx = index + 1
                direction = 1
            else:
                sibling_idx = index - 1
                direction = 0
            proof.append((direction, padded[sibling_idx]))
            index //= 2
        return proof


def verify_proof(leaf: str, proof: list, root: str) -> bool:
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
    root = tree.get_root()
    print("Merkle Root:", root)
    for i, sub in enumerate(subs):
        ok = verify_proof(sub, tree.get_proof(i), root)
        print(f"  {sub}: {'PASS' if ok else 'FAIL'}")
    print("  evil:", verify_proof("evil", tree.get_proof(0), root))

