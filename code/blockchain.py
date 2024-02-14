from typing import List, Any

class Blockchain:
    def __init__(self, blocks:List[Any]=[]):
        self.blocks = blocks

    def add_block_to_chain(self, block):
        self.blocks.append(block)