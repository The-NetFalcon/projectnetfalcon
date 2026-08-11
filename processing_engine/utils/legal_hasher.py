"""
legal_hasher.py
---------------

Maintains a tamper-evident chain of evidence using SHA-256.
"""

import hashlib
import json
import os
import time
import uuid


class LegalHasher:

    def __init__(self, vault_path):

        self.vault_path = vault_path

        if not os.path.exists(vault_path):

            with open(vault_path, "w") as f:
                json.dump([], f)

    def _load(self):

        with open(self.vault_path, "r") as f:
            return json.load(f)

    def _save(self, chain):

        with open(self.vault_path, "w") as f:
            json.dump(chain, f, indent=4)

    def add_evidence(self, evidence, actor="processing_engine"):

        chain = self._load()

        previous_hash = (
            chain[-1]["evidence_hash"]
            if chain
            else "GENESIS"
        )

        block = {

            "evidence_id": str(uuid.uuid4()),

            "timestamp": time.time(),

            "actor": actor,

            "previous_hash": previous_hash,

            "evidence": evidence

        }

        raw = json.dumps(
            block,
            sort_keys=True
        ).encode()

        block["evidence_hash"] = hashlib.sha256(raw).hexdigest()

        chain.append(block)

        self._save(chain)

        return block

    def verify_chain(self):

        chain = self._load()

        previous = "GENESIS"

        for index, block in enumerate(chain):

            original_hash = block["evidence_hash"]

            temp = dict(block)

            del temp["evidence_hash"]

            raw = json.dumps(
                temp,
                sort_keys=True
            ).encode()

            calculated = hashlib.sha256(raw).hexdigest()

            if calculated != original_hash:

                return False, index

            if block["previous_hash"] != previous:

                return False, index

            previous = original_hash

        return True, None

    def get_evidence(self, evidence_id):

        chain = self._load()

        for block in chain:

            if block["evidence_id"] == evidence_id:

                return block

        return None

    def all_evidence(self):

        return self._load()