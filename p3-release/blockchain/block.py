from abc import ABC, abstractmethod # We want to make Block an abstract class; either a PoW or PoA block
import blockchain
from blockchain.util import sha256_2_string, encode_as_str
import time
import persistent
from blockchain.util import nonempty_intersection
from math import log2, ceil

class Block(ABC, persistent.Persistent):

    def __init__(self, height, transactions, parent_hash, is_genesis=False, timestamp=time.time(),
            target=None, merkle=None, seal_data=0):
        """ Creates a block template (unsealed).

        Args:
            height (int): height of the block in the chain (# of blocks between block and genesis).
            transactions (:obj:`list` of :obj:`Transaction`): ordered list of transactions in the block.
            parent_hash (str): the hash of the parent block in the blockchain.
            is_genesis (bool, optional): True only if the block is a genesis block.

        Attributes:
            parent_hash (str): the hash of the parent block in blockchain.
            height (int): height of the block in the chain (# of blocks between block and genesis).
            transactions (:obj:`list` of :obj:`Transaction`): ordered list of transactions in the block.
            timestamp (int): Unix timestamp of the block
            target (int): Target value for the block's seal to be valid (different for each seal mechanism)
            is_genesis (bool): True only if the block is a genesis block (first block in the chain).
            merkle (str): Merkle hash of the list of transactions in a block, uniquely identifying the list.
            seal_data (int): Seal data for block (in PoW this is the nonce satisfying the PoW puzzle; in PoA, the signature of the authority"
            hash (str): Hex-encoded SHA256^2 hash of the block header (self.header())
        """
        self.parent_hash = parent_hash
        self.height = height
        self.transactions = transactions
        self.timestamp = timestamp
        self.target = target
        self.is_genesis = is_genesis
        self.merkle = merkle
        self.seal_data = seal_data
        if target == None:
            self.target = self.calculate_appropriate_target()
        if merkle == None:
            self.merkle = self.calculate_merkle_root()
        self.hash = self.calculate_hash() # keep track of hash for caching purposes

    def calculate_merkle_root(self):
        """ Gets the Merkle root hash for a given list of transactions.

        This method is incomplete!  Right now, it only hashes the
        transactions together, which does not enable the same type
        of lite client support a true Merkle hash would.
        You do not need to complete this except for the bonus question.

        Returns:
            str: Merkle hash of the list of transactions in a block, uniquely identifying the list.
        """

        if len(self.transactions) == 0:
            return sha256_2_string("")
        elif len(self.transactions) == 1:
            return sha256_2_string(str(self.transactions[0]))
        else:
            total = len(self.transactions)
            levels = 1 + ceil(log2(total))
            treenodes = [None] * levels
            for i in range(levels):
                treenodes[i] = [None] * (1 << i)

            level = levels - 1
            for i in range(1 << level):
                if i < len(self.transactions):
                    treenodes[level][i] = sha256_2_string(str(self.transactions[i]))
                else:
                    treenodes[level][i] = sha256_2_string("")
            while level > 0:
                level = level - 1
                for i in range(1 << level):
                    treenodes[level][i] = sha256_2_string(treenodes[level + 1][2*i] + treenodes[level + 1][2*i + 1])

            return treenodes[0][0]

    def unsealed_header(self):
        """ Computes the header string of a block (the component that is sealed by mining).

        Returns:
            str: String representation of the block header without the seal.
        """
        return encode_as_str([self.height, self.timestamp, self.target, self.parent_hash, self.is_genesis, self.merkle], sep='`')

    def header(self):
        """ Computes the full header string of a block after mining (includes the seal).

        Returns:
            str: String representation of the block header.
        """
        return encode_as_str([self.unsealed_header(), self.seal_data], sep='`')

    def calculate_hash(self):
        """ Get the SHA256^2 hash of the block header.

        Returns:
            str: SHA256^2 hash of self.header()
        """
        return sha256_2_string(str(self.header()))

    def __repr__(self):
        """ Get a full representation of a block as string, for debugging purposes; includes all transactions.

        Returns:
            str: Full and unique representation of a block and its transactions.
        """
        return encode_as_str([self.header(), "!".join([str(tx) for tx in self.transactions])], sep="`")

    def set_seal_data(self, seal_data):
        """ Adds seal data to a block, recomputing the block's hash for its changed header representation.
        This method should never be called after a block is added to the blockchain!

        Args:
            seal_data (int): The seal data to set.
        """
        self.seal_data = seal_data
        self.hash = self.calculate_hash()

    def is_valid(self):
        """ Check whether block is fully valid according to block rules.

        Includes checking for no double spend, that all transactions are valid, that all header fields are correctly
        computed, etc.

        Returns:
            bool, str: True if block is valid, False otherwise plus an error or success message.
        """

        chain = blockchain.chaindb.chain # This object of type Blockchain may be useful

        # Paste your answers to problem 1 here
        # Be aware not to copy the first line (i.e. chain = blockchain.chain)

        


        return True, "All checks passed"


    # ( these just establish methods for subclasses to implement; no need to modify )
    @abstractmethod
    def get_weight(self):
        """ Should be implemented by subclasses; gives consensus weight of block. """
        pass

    @abstractmethod
    def calculate_appropriate_target(self):
        """ Should be implemented by subclasses; calculates correct target to use in block. """
        pass

    @abstractmethod
    def seal_is_valid(self):
        """ Should be implemented by subclasses; returns True iff the seal_data creates a valid seal on the block. """
        pass
