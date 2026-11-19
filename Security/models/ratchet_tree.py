from dataclasses import dataclass
from __future__ import annotations
from .key_package import PublicKeyPackage

@dataclass
class RatchetTree:
    def __init__(self):
        self.root: TreeNode | None = None
        self._leaves: list[TreeNode] = []
    
    def insert_member(self, package: PublicKeyPackage) -> int:
        leaf_index = len(self._leaves)
        leaf = TreeNode(
            node_index=2 * leaf_index, 
            public_key=package.public_key
        )
        if self.root is None:
            self.root = leaf
            self._leaves.append(leaf)
            return leaf_index
        
        subtree_size = leaf_index & -leaf_index
        leftmost_node_index = 2 * (leaf_index - subtree_size)
        subtree = self._leaves[-1]

        while (subtree.parent is not None and subtree.parent.node_index >= leftmost_node_index):
            subtree = subtree.parent
        
        previous_parent = subtree.parent
        new_parent = TreeNode(
            node_index = leaf.node_index - 1,
            public_key=b"",
            parent=previous_parent,
            left=subtree,
            right=leaf,
        )

        if previous_parent is None:
            self.root = new_parent
        else:
            previous_parent.right = new_parent

        subtree.parent = new_parent
        leaf.parent = new_parent
        self._leaves
        return leaf_index

    def get_leaf(self, leaf_index: int) -> TreeNode:
        if not 0 <= leaf_index < len(self._leaves):
            raise IndexError(f"Leaf index {leaf_index} is out of bounds.")
        return self._leaves[leaf_index]
        
    def print_tree(self) -> None:
        
        if self.root is None:
            print("Ratchet tree is empty.")
            return

        def print_node(node: TreeNode, label: str, depth: int) -> None:
            indent = "    " * depth
            details = f"node={node.node_index}"
            if node.is_leaf():
                details += f", leaf={node.node_index // 2}"

            public_key = node.public_key.hex() if node.public_key else "(unset)"
            print(f"{indent}{label} [{details}] public_key={public_key}")

            if node.left is not None:
                print_node(node.left, "Left", depth + 1)
            if node.right is not None:
                print_node(node.right, "Right", depth + 1)

        print_node(self.root, "Root", 0)

@dataclass(eq=False)
class TreeNode:
    node_index: int
    public_key: bytes
    parent: TreeNode | None = None,
    left: TreeNode | None = None,
    right: TreeNode | None = None,

    def is_leaf(self) -> bool:
        return self.left is None and self.right is None 