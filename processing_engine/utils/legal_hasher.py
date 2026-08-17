"""
legal_hasher.py
---------------

Maintains a tamper-evident chain of evidence using SHA-256.

The vault is protected by a process-local lock and atomic file replacement
so concurrent flow requests cannot corrupt the JSON evidence store.
"""

import hashlib
import json
import os
import tempfile
import time
import uuid
import threading


class LegalHasher:

    def __init__(self, vault_path):
        self.vault_path = vault_path
        self._lock = threading.RLock()

        if not os.path.exists(vault_path):
            self._atomic_save([])

    def _load(self):
        with self._lock:
            with open(self.vault_path, "r", encoding="utf-8") as f:
                return json.load(f)

    def _atomic_save(self, chain):
        directory = os.path.dirname(os.path.abspath(self.vault_path)) or "."

        fd, temp_path = tempfile.mkstemp(
            prefix=".evidence_vault_",
            suffix=".tmp",
            dir=directory,
            text=True,
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(chain, f, indent=4)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, self.vault_path)

        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    def _save(self, chain):
        with self._lock:
            self._atomic_save(chain)

    def add_evidence(self, evidence, actor="processing_engine"):
        with self._lock:
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
                "evidence": evidence,
            }

            raw = json.dumps(
                block,
                sort_keys=True,
            ).encode("utf-8")

            block["evidence_hash"] = hashlib.sha256(raw).hexdigest()

            chain.append(block)
            self._atomic_save(chain)

            return block

    def verify_chain(self):
        with self._lock:
            chain = self._load()

            previous = "GENESIS"

            for index, block in enumerate(chain):
                original_hash = block["evidence_hash"]

                temp = dict(block)
                del temp["evidence_hash"]

                raw = json.dumps(
                    temp,
                    sort_keys=True,
                ).encode("utf-8")

                calculated = hashlib.sha256(raw).hexdigest()

                if calculated != original_hash:
                    return False, index

                if block["previous_hash"] != previous:
                    return False, index

                previous = original_hash

            return True, None

    def get_evidence(self, evidence_id):
        with self._lock:
            chain = self._load()

            for block in chain:
                if block["evidence_id"] == evidence_id:
                    return block

            return None

    def all_evidence(self):
        with self._lock:
            return self._load()