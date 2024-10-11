import os
import numpy as np
import secrets
import hashlib
import pickle
import ctypes
from sympy import nextprime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Helper function for secure weighted choice ---
def weighted_choice(items, weights):
    clamped_weights = [max(0, w) for w in weights]
    total = sum(clamped_weights)  # Sum of clamped weights

    if total == 0:
        return items[0]  # Return the first item if all weights are zero

    cumulative_weights = [sum(clamped_weights[:i + 1]) for i in range(len(clamped_weights))]
    rand = secrets.SystemRandom().uniform(0, total)
    for i, weight in enumerate(cumulative_weights):
        if rand < weight:
            return items[i]
    return items[-1]

# --- Qubit Class for Quantum Operations ---
class Qubit:
    def __init__(self, label="qubit"):
        self.label = label
        self.state = np.array([complex(1, 0), complex(0, 0)], dtype=np.complex128)  # Default state
        self.private_entangled_partner = None  # Entangled with a private qubit
        self.normalize()

    def normalize(self):
        norm = np.linalg.norm(self.state)
        if norm == 0:
            self.state = np.array([1, 0], dtype=np.complex128)  # Reset to a default state if invalid
            norm = 1
        self.state = self.state / norm

    def apply_hadamard(self):
        H = np.array([[1, 1],
                      [1, -1]], dtype=np.complex128) / np.sqrt(2)
        self.apply_gate(H)

    def phase_gate(self, theta):
        T = np.array([[1, 0],
                      [0, np.exp(1j * theta)]], dtype=np.complex128)
        self.apply_gate(T)

    def apply_gate(self, gate_matrix):
        self.state = np.dot(gate_matrix, self.state)
        self.normalize()

    def apply_pauli(self, gate):
        if gate == 'X':
            P = np.array([[0, 1],
                          [1, 0]], dtype=np.complex128)
        elif gate == 'Y':
            P = np.array([[0, -1j],
                          [1j, 0]], dtype=np.complex128)
        elif gate == 'Z':
            P = np.array([[1, 0],
                          [0, -1]], dtype=np.complex128)
        else:
            raise ValueError("Unknown Pauli gate.")
        self.apply_gate(P)

    def measure(self):
        probabilities = np.abs(self.state) ** 2
        if sum(probabilities) == 0:
            raise ValueError("Invalid state: both probabilities are zero.")
        result = weighted_choice([0, 1], probabilities)
        self.state = np.array([1, 0] if result == 0 else [0, 1], dtype=np.complex128)
        # Apply measurement collapse to entangled partners
        if self.private_entangled_partner:
            self.private_entangled_partner.state = self.state.copy()
        return result

    def put_back_in_superposition(self):
        self.apply_hadamard()
        pauli_gates = ['X', 'Y', 'Z']
        secrets.SystemRandom().shuffle(pauli_gates)  # Securely shuffle the Pauli gates
        for gate in pauli_gates:
            num_repetitions = secrets.SystemRandom().randint(1, 3)
            for _ in range(num_repetitions):
                self.apply_pauli(gate)
                theta = secrets.SystemRandom().uniform(0, 2 * np.pi)
                self.phase_gate(theta)

    def entangle_with_private(self, private_qubit):
        # Ensure no existing entanglement
        if self.private_entangled_partner is not None and self.private_entangled_partner is not private_qubit:
            self.disentangle_private()
        if private_qubit.private_entangled_partner is not None and private_qubit.private_entangled_partner is not self:
            private_qubit.disentangle_private()

        if self.private_entangled_partner is None and private_qubit.private_entangled_partner is None:
            self.private_entangled_partner = private_qubit
            private_qubit.private_entangled_partner = self
            self.apply_hadamard()
            private_qubit.apply_hadamard()
            print(f"{self.label} entangled with {private_qubit.label} ")
        elif self.private_entangled_partner is private_qubit:
            pass  # Already entangled with this private qubit
        else:
            print(f"{self.label} cannot entangle with {private_qubit.label} (already entangled).")

    def disentangle_private(self):
        if self.private_entangled_partner:
            print(f"{self.label} disentangled from {self.private_entangled_partner.label}")
            partner = self.private_entangled_partner
            self.private_entangled_partner = None
            partner.private_entangled_partner = None

# --- XMSS (Extended Merkle Signature Scheme) Class for Post-Quantum Signatures ---
class XMSS:
    def __init__(self, height=10, n=32):
        self.height = height
        self.n = n
        self.sk_seed = os.urandom(self.n)
        self.pub_seed = os.urandom(self.n)
        self.leaves = [self._hash(self.sk_seed + i.to_bytes(4, byteorder='big')) for i in range(2 ** self.height)]
        self.root = self._compute_merkle_root(self.leaves)
        self.index = 0

    def _hash(self, data):
        return hashlib.sha256(data).digest()

    def _compute_merkle_root(self, leaves):
        nodes = leaves
        while len(nodes) > 1:
            # If odd number of nodes, duplicate the last node
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1])
            nodes = [self._hash(nodes[i] + nodes[i + 1]) for i in range(0, len(nodes), 2)]
        return nodes[0]

    def sign(self, message):
        if self.index >= 2 ** self.height:
            raise ValueError("XMSS key exhausted.")
        signature = self._hash(self.leaves[self.index] + message)
        auth_path = self._get_auth_path(self.index)
        self.index += 1
        return {'signature': signature, 'auth_path': auth_path, 'index': self.index - 1}

    def _get_auth_path(self, index):
        auth_path = []
        for _ in range(self.height):
            sibling = index ^ 1
            auth_path.append(self.leaves[sibling])
            index //= 2
        return auth_path

# --- KeySplit Class for Shred Key Management ---
class KeySplit:
    def __init__(self, private_key=None, salt=None):
        if private_key is None:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self.salt = salt if salt is not None else os.urandom(32)  # Each KeySplit has its own salt

    def serialize(self):
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,  # Use PKCS8 for compatibility
            encryption_algorithm=serialization.NoEncryption()
        )
        salt = self.salt
        return {
            'private_key': private_bytes,
            'salt': salt
        }

    @staticmethod
    def deserialize(data):
        private_key = serialization.load_pem_private_key(
            data['private_key'],
            password=None
        )
        salt = data['salt']
        return KeySplit(private_key=private_key, salt=salt)

# --- ShredCipher Class ---
class ShredCipher:
    def __init__(self, num_splits=8, shred_key_splits=None, subkey_shred_keys=None, xmss=None):
        self.num_splits = num_splits
        self.shred_key_splits = shred_key_splits if shred_key_splits is not None else []
        self.subkey_shred_keys = subkey_shred_keys if subkey_shred_keys is not None else []
        self.qubit_identifiers = {}
        self.shred_private_key = None
        self.shred_public_key = None
        self.xmss = xmss if xmss is not None else XMSS(height=10)
        if not self.shred_key_splits:
            self.generate_keys()
        if not self.subkey_shred_keys:
            self.generate_and_split_initial_key()
        self.generate_qubit_identifiers()

    def generate_keys(self):
        self.shred_private_key = ec.generate_private_key(ec.SECP256R1())
        self.shred_public_key = self.shred_private_key.public_key()
        for _ in range(self.num_splits):
            keysplit = KeySplit()
            self.shred_key_splits.append(keysplit)

    def generate_and_split_initial_key(self):
        shred_key = secrets.token_bytes(32)  # Generate Shred-256 key
        encrypted_key = self._encrypt_with_shred(shred_key)
        self._split_key(encrypted_key)

    def _encrypt_with_shred(self, shred_key):
        encrypted_key = b''
        for keysplit in self.shred_key_splits:
            private_key = keysplit.private_key
            public_key = keysplit.public_key
            shared_secret = private_key.exchange(ec.ECDH(), public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=keysplit.salt,
                info=b'shred derived'
            ).derive(shared_secret)
            aesgcm = AESGCM(derived_key)
            nonce = secrets.token_bytes(12)  # AES-GCM nonce size
            encrypted_chunk = aesgcm.encrypt(nonce, shred_key, None)
            encrypted_key += nonce + encrypted_chunk
        return encrypted_key

    def _split_key(self, encrypted_key):
        subkey_length = len(encrypted_key) // self.num_splits
        self.subkey_shred_keys = [
            encrypted_key[i * subkey_length: (i + 1) * subkey_length]
            for i in range(self.num_splits)
        ]

    def generate_qubit_identifiers(self):
        for i in range(self.num_splits):
            public_qubit = Qubit(label=f"public indicator {i+1}")
            private_qubit = Qubit(label=f"private indicator {i+1}")
            theta_public = secrets.SystemRandom().uniform(0, 2 * np.pi)
            theta_private = secrets.SystemRandom().uniform(0, 2 * np.pi)
            public_qubit.apply_hadamard()
            private_qubit.apply_hadamard()
            public_qubit.phase_gate(theta_public)
            private_qubit.phase_gate(theta_private)
            self.qubit_identifiers[i] = {'public': public_qubit, 'private': private_qubit}
            public_qubit.entangle_with_private(private_qubit)

    def custom_dh(self, subkey_indices, measurements=None):
        num_subkeys = len(subkey_indices)
        partial_secrets = []
        measurement_results = measurements or {}

        # Step 1: Cyclic Entanglement and Measurement
        for i in range(num_subkeys):
            pub_idx = subkey_indices[i]
            priv_idx = subkey_indices[(i + 1) % num_subkeys]

            public_qubit = self.qubit_identifiers[pub_idx]['public']
            private_qubit = self.qubit_identifiers[priv_idx]['private']

            # Entangle public qubit with the next private qubit in the cycle
            public_qubit.entangle_with_private(private_qubit)

            # Perform measurement
            if measurements is None:
                measurement = public_qubit.measure()
                measurement_results[pub_idx] = measurement
            else:
                measurement = measurement_results[pub_idx]
                # Set the public qubit's state based on the measurement
                if measurement == 0:
                    public_qubit.state = np.array([1, 0], dtype=np.complex128)
                else:
                    public_qubit.state = np.array([0, 1], dtype=np.complex128)
                # Collapse the private qubit's state
                if public_qubit.private_entangled_partner:
                    public_qubit.private_entangled_partner.state = public_qubit.state.copy()

            # Disentangle public qubit from the cycled private qubit
            public_qubit.disentangle_private()

            # Generate P and Q for Diffie-Hellman based on the measurement
            public_subkey = self.subkey_shred_keys[pub_idx]
            private_subkey = self.subkey_shred_keys[priv_idx]
            p = self.get_prime_from_subkey(public_subkey)
            q = self.get_generator_from_subkey(private_subkey, p)

            # Deterministically derive private_value
            private_value_seed = hashlib.sha256(private_subkey + bytes([measurement])).digest()
            private_value = int.from_bytes(private_value_seed, 'big') % (p - 2) + 1

            public_value = pow(q, private_value, p)

            # Simulate exchange of public values
            shared_secret = pow(public_value, private_value, p)
            shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')

            # Hash the measurement with shared secret
            partial_secret = hashlib.sha256(shared_secret_bytes + bytes([measurement])).digest()
            partial_secrets.append(partial_secret)

        # Step 2: Combine all partial secrets to form the cumulative secret
        cumulative_secret = hashlib.sha256(b''.join(partial_secrets)).digest()

        # Combine all salts from the used KeySplits
        combined_salt = b''.join([self.shred_key_splits[i].salt for i in subkey_indices])

        master_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=combined_salt,
            info=b'quantum-dh'
        ).derive(cumulative_secret)

        # Step 3: Re-Entangle Public Qubits with Their Own Private Qubits
        for i in subkey_indices:
            public_qubit = self.qubit_identifiers[i]['public']
            private_qubit = self.qubit_identifiers[i]['private']

            # Disentangle if necessary
            public_qubit.disentangle_private()
            private_qubit.disentangle_private()

            # Reset qubits
            public_qubit.put_back_in_superposition()
            private_qubit.put_back_in_superposition()

            # Re-entangle public qubit with its own private qubit
            public_qubit.entangle_with_private(private_qubit)

        return master_key, measurement_results  # Return measurement results

    def get_prime_from_subkey(self, subkey):
        subkey_hash = hashlib.sha256(subkey).hexdigest()
        prime_candidate = int(subkey_hash, 16)
        return nextprime(prime_candidate)

    def get_generator_from_subkey(self, subkey, p):
        subkey_hash = hashlib.sha256(subkey).hexdigest()
        g_candidate = int(subkey_hash, 16) % p
        if g_candidate <= 1:
            return 2
        return g_candidate

    def encrypt(self, data, subkey_indices=None, use_quantum=True):
        if subkey_indices is None:
            subkey_indices = list(range(self.num_splits))
        master_key, measurement_results = self.custom_dh(subkey_indices, measurements=None)
        nonce = os.urandom(12)  # AES-GCM nonce size
        aesgcm = AESGCM(master_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        message_digest = hashlib.sha256(data).digest()  # Hash the message
        xmss_signature = self.xmss.sign(message_digest)  # Sign using XMSS

        self._clear_assembled_key(master_key)
        return ciphertext, nonce, xmss_signature, measurement_results

    def decrypt(self, ciphertext, nonce, xmss_signature, subkey_indices=None, measurements=None, use_quantum=True):
        if subkey_indices is None:
            subkey_indices = list(range(self.num_splits))
        if measurements is None:
            raise ValueError("Measurements must be provided for decryption.")
        master_key, _ = self.custom_dh(subkey_indices, measurements=measurements)
        aesgcm = AESGCM(master_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

        message_digest = hashlib.sha256(decrypted_data).digest()
        expected_signature = self.xmss._hash(self.xmss.leaves[xmss_signature['index']] + message_digest)
        if xmss_signature['signature'] != expected_signature:
            raise ValueError("Invalid XMSS signature. Data integrity compromised.")

        self._clear_assembled_key(master_key)
        return decrypted_data

    def _clear_assembled_key(self, key):
        mutable_key = bytearray(key)
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(mutable_key)), 0, len(mutable_key))
        print("Assembled key cleared from memory.")

# --- File Output Functions using Binary format ---
def save_to_bin_file(filename, ciphertext, nonce, xmss_signature, measurement_results):
    with open(filename, 'wb') as f:
        # Serialize using pickle to handle complex data
        data = {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'xmss_signature': xmss_signature,
            'measurement_results': measurement_results
        }
        pickle.dump(data, f)  # Save in binary format

def load_from_bin_file(filename):
    with open(filename, 'rb') as f:
        # Deserialize using pickle
        data = pickle.load(f)

    ciphertext = data['ciphertext']
    nonce = data['nonce']
    xmss_signature = data['xmss_signature']
    measurement_results = data['measurement_results']

    return ciphertext, nonce, xmss_signature, measurement_results

# --- Example Usage ---

def main():
    # Encryption
    cipher = ShredCipher()
    subkey_indices = [0, 1, 2,7]  # Example subkeys for A, B, C
    message = b"This update is a hot fix for salts and entanglement which also includes binary file I/O!"

    print("\nEncrypting message...")
    encrypted_message, nonce, xmss_signature, measurement_results = cipher.encrypt(message, subkey_indices, use_quantum=True)
    print(f"Encrypted message: {encrypted_message.hex()}\n")

    # Save the results to a binary file
    save_to_bin_file('encrypted_data.bin', encrypted_message, nonce, xmss_signature, measurement_results)

    # Save the cipher's state (serialize keys)
    with open('cipher_state.pkl', 'wb') as f:
        # Serialize KeySplit objects
        shred_key_splits_serialized = [keysplit.serialize() for keysplit in cipher.shred_key_splits]
        # Serialize XMSS
        xmss_serialized = pickle.dumps(cipher.xmss)
        # Save other necessary state
        pickle.dump({
            'shred_key_splits': shred_key_splits_serialized,
            'subkey_shred_keys': cipher.subkey_shred_keys,
            'xmss_serialized': xmss_serialized
        }, f)

    # Decryption
    # Load the cipher's state
    with open('cipher_state.pkl', 'rb') as f:
        cipher_state = pickle.load(f)

    # Deserialize KeySplit objects
    shred_key_splits = [KeySplit.deserialize(data) for data in cipher_state['shred_key_splits']]
    # Deserialize XMSS
    xmss = pickle.loads(cipher_state['xmss_serialized'])

    # Create a new cipher instance and load the state
    cipher = ShredCipher(
        shred_key_splits=shred_key_splits,
        subkey_shred_keys=cipher_state['subkey_shred_keys'],
        xmss=xmss
    )

    # Load the results from the binary file
    loaded_encrypted_message, loaded_nonce, loaded_xmss_signature, loaded_measurement_results = load_from_bin_file('encrypted_data.bin')

    print("Decrypting message...")
    decrypted_message = cipher.decrypt(
        loaded_encrypted_message,
        loaded_nonce,
        loaded_xmss_signature,
        subkey_indices,
        measurements=loaded_measurement_results,
        use_quantum=True
    )
    print(f"Decrypted message: {decrypted_message.decode()}\n")

if __name__ == "__main__":
    main()
