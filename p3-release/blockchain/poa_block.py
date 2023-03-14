from blockchain.block import Block
from blockchain import util
import config

class PoABlock(Block):
    """ Extends Block, adding proof-of-work primitives. """

    def seal_is_valid(self):
        """ Checks whether a block's seal_data forms a valid seal.
            In PoA, this means that Verif(PK, [block, sig]) = accept.
            (aka the unsealed block header is validly signed under the authority's public key)

            Returns:
                bool: True only if a block's seal data forms a valid seal according to PoA.
        """
        if self.seal_data == 0:
            return False

        # Decode signature to bytes, verify it
        signature = hex(self.seal_data)[2:].zfill(96)
        return util.is_message_signed(self.unsealed_header(), signature, config.AUTHORITY_PK)

    def get_weight(self):
        """ All blocks have same weight in PoA """
        return 1

    def mine(self):
        """ PoA signer; seals a block with new seal data by signing it, checking that
            signature is valid, and returning.
        """

        # Paste your answers to problem 1 here
        header_bytes = bytes(self.unsealed_header(), 'utf-8')
        signing_key = bytes.fromhex(config.AUTHORITY_SK)

        sk = SigningKey.from_string(signing_key, curve=ecdsa.NIST192p)
        signature = sk.sign(header_bytes)

        self.set_seal_data(int(signature.hex(), 16))

    def calculate_appropriate_target(self):
        """ Target in PoA is currently meaningless """
        return 0

