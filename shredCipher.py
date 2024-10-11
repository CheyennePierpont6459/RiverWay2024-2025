import os
import numpy as np
import secrets
import hashlib
import struct
import pickle
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ctypes

# --- Helper function for secure weighted choice ---
def weighted_choice(items, weights):
    clamped_weights = [max(0, w) for w in weights]
    total = int(sum(clamped_weights))  # Sum of clamped weights

    if total == 0:
        return items[0]  # Return the first item if all weights are zero

    cumulative_weights = [int(sum(clamped_weights[:i + 1])) for i in range(len(clamped_weights))]
    rand = secrets.randbelow(total)
    for i, weight in enumerate(cumulative_weights):
        if rand < weight:
            return items[i]

# --- Qubit Class for Quantum Operations ---
class Qubit:
    def __init__(self, label="qubit"):
        self.label = label
        self.state = np.array([complex(1, 0), complex(0, 0)], dtype=np.complex128)  # Default state
        self.entangled_partner = None  # Reference to the entangled qubit
        self.normalize()

    def normalize(self):
        norm = np.linalg.norm(self.state)
        if norm == 0:
            self.state = np.array([1, 0], dtype=np.complex128)  # Reset to a default state if invalid
            norm = 1
        self.state = self.state / norm

    def apply_hadamard(self):
        H = np.array([[1 / np.sqrt(2), 1 / np.sqrt(2)], [1 / np.sqrt(2), -1 / np.sqrt(2)]], dtype=np.complex128)
        self.apply_gate(H)

    def phase_gate(self, theta):
        T = np.array([[1, 0], [0, np.exp(1j * theta)]], dtype=np.complex128)
        self.apply_gate(T)

    def apply_gate(self, gate_matrix):
        self.state = np.dot(gate_matrix, self.state)
        self.normalize()

    def apply_pauli(self, gate):
        if gate == 'X':
            P = np.array([[0, 1], [1, 0]], dtype=np.complex128)
        elif gate == 'Y':
            P = np.array([[0, -1j], [1j, 0]], dtype=np.complex128)
        elif gate == 'Z':
            P = np.array([[1, 0], [0, -1]], dtype=np.complex128)
        else:
            raise ValueError("Unknown Pauli gate.")
        self.apply_gate(P)

    def measure(self):
        probabilities = np.abs(self.state) ** 2
        if sum(probabilities) == 0:
            raise ValueError("Invalid state: both probabilities are zero.")
        result = weighted_choice([0, 1], probabilities)
        self.state = np.array([1, 0] if result == 0 else [0, 1], dtype=np.complex128)
        if self.entangled_partner:
            self.entangled_partner.state = self.state
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

    def entangle(self, other_qubit):
        # Only perform entanglement if not already entangled
        if self.entangled_partner is not other_qubit:
            self.entangled_partner = other_qubit
            other_qubit.entangled_partner = self
            self.apply_hadamard()
            other_qubit.apply_hadamard()
            print(f"{self.label} entangled with {other_qubit.label}.")

    def disentangle(self):
        # Only perform disentanglement if currently entangled
        if self.entangled_partner:
            print(f"{self.label} disentangled from {self.entangled_partner.label}.")
            self.entangled_partner.entangled_partner = None
            self.entangled_partner = None

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
        for i in range(self.height):
            sibling = index ^ 1
            auth_path.append(self.leaves[sibling])
            index //= 2
        return auth_path

# --- KeySplit Class for Shred Key Management ---
class KeySplit:
    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.salt = os.urandom(32)  # Each KeySplit has its own salt

# --- ShredCipher Class ---
class ShredCipher:
    def __init__(self, num_splits=8, shred_key_size=2048, shred_public_exponent=65537):
        self.num_splits = num_splits
        self.shred_key_splits = []
        self.subkey_shred_keys = []
        self.qubit_identifiers = {}
        self.shred_private_key, self.shred_public_key = None, None
        self.xmss = XMSS(height=10)  # XMSS instance for signing
        self.generate_keys()
        self.generate_and_split_initial_key()
        self.generate_qubit_identifiers()

    def generate_keys(self):
        self.shred_private_key = ec.generate_private_key(ec.SECP256R1())
        self.shred_public_key = self.shred_private_key.public_key()
        for _ in range(self.num_splits):
            private_key = ec.generate_private_key(ec.SECP256R1())
            self.shred_key_splits.append(KeySplit(private_key))

    def generate_and_split_initial_key(self):
        shred_key = secrets.token_bytes(32)  # Generate Shred-256 key
        encrypted_key = self._encrypt_with_shred(shred_key)
        self._split_key(encrypted_key)

    def _encrypt_with_shred(self, shred_key):
        encrypted_key = b''
        for keysplit in self.shred_key_splits:
            private_key, public_key = keysplit.private_key, keysplit.public_key
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
        self.subkey_shred_keys = [encrypted_key[i * subkey_length: (i + 1) * subkey_length] for i in range(self.num_splits)]

    def generate_qubit_identifiers(self):
        for i in range(self.num_splits):
            public_qubit = Qubit(label=f"public indicator {i+1}")
            private_qubit = Qubit(label=f"private indicator {i+1}")
            public_qubit.apply_hadamard()
            private_qubit.apply_hadamard()
            theta_public = secrets.SystemRandom().uniform(0, 2 * np.pi)
            theta_private = secrets.SystemRandom().uniform(0, 2 * np.pi)
            public_qubit.phase_gate(theta_public)
            private_qubit.phase_gate(theta_private)
            self.qubit_identifiers[i] = {'public': public_qubit, 'private': private_qubit}
            public_qubit.entangle(private_qubit)

    def custom_dh(self, subkey_indices, measurements=None):
        num_subkeys = len(subkey_indices)
        partial_secrets = []
        measurement_results = measurements or {}

        for i in range(num_subkeys):
            subkey_a_index = subkey_indices[i]
            subkey_b_index = subkey_indices[(i + 1) % num_subkeys]  # Circular neighbor

            public_a = self.qubit_identifiers[subkey_a_index]['public']
            public_b = self.qubit_identifiers[subkey_b_index]['public']
            public_a.disentangle()
            public_b.disentangle()
            public_a.entangle(public_b)

            if measurements is None:
                measurement_a = public_a.measure()
                measurement_b = public_b.measure()
                measurement_results[subkey_a_index] = (measurement_a, measurement_b)
            else:
                measurement_a, measurement_b = measurement_results[subkey_a_index]

            public_a.entangle(self.qubit_identifiers[subkey_a_index]['private'])
            public_b.entangle(self.qubit_identifiers[subkey_b_index]['private'])

            subkey_a = self.subkey_shred_keys[subkey_a_index]
            subkey_b = self.subkey_shred_keys[subkey_b_index]

            # Use the salt from the KeySplit object
            salt_a = self.shred_key_splits[subkey_a_index].salt
            salt_b = self.shred_key_splits[subkey_b_index].salt

            partial_secret = hashlib.sha256(
                subkey_a + subkey_b + bytes([measurement_a, measurement_b]) + salt_a + salt_b
            ).digest()
            partial_secrets.append(partial_secret)

            public_a.disentangle()
            public_a.entangle(self.qubit_identifiers[subkey_a_index]['private'])

            if measurements is None:
                self_measurement_a = public_a.measure()
                measurement_results[f'self_{subkey_a_index}'] = self_measurement_a
            else:
                self_measurement_a = measurement_results[f'self_{subkey_a_index}']

            partial_secret_self = hashlib.sha256(
                subkey_a + bytes([self_measurement_a]) + salt_a
            ).digest()
            partial_secrets.append(partial_secret_self)

        cumulative_secret = hashlib.sha256(b''.join(partial_secrets)).digest()

        # Combine all salts from the used KeySplits
        combined_salt = b''.join([self.shred_key_splits[i].salt for i in subkey_indices])

        master_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=combined_salt,
            info=b'quantum-derived'
        ).derive(cumulative_secret)

        # After completing the DH process, reset all qubits back into superposition and entangle them
        for i in subkey_indices:
            self.qubit_identifiers[i]['public'].put_back_in_superposition()
            self.qubit_identifiers[i]['private'].put_back_in_superposition()
            self.qubit_identifiers[i]['public'].entangle(self.qubit_identifiers[i]['private'])

        return master_key, measurement_results  # Return measurement results

    def encrypt(self, data, subkey_indices=None, use_quantum=True):
        master_key, measurement_results = self.custom_dh(subkey_indices)  # Use the DH-generated master key
        nonce = os.urandom(12)  # AES-GCM nonce size
        aesgcm = AESGCM(master_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        message_digest = hashlib.sha256(data).digest()  # Hash the message
        xmss_signature = self.xmss.sign(message_digest)  # Sign using XMSS

        self._clear_assembled_key(master_key)
        return ciphertext, nonce, xmss_signature, measurement_results

    def decrypt(self, ciphertext, nonce, xmss_signature, subkey_indices=None, measurements=None, use_quantum=True):
        master_key, _ = self.custom_dh(subkey_indices, measurements=measurements)  # Use the same measurements
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
    cipher = ShredCipher()
    subkey_indices = [0, 1, 3, 5, 6]  # Example subkeys
    message = b"This update is a hot fix for salts and entanglement which also includes binary file I/O!"

    print("\nEncrypting message...")
    encrypted_message, nonce, xmss_signature, measurement_results = cipher.encrypt(message, subkey_indices, use_quantum=True)
    print(f"Encrypted message: {encrypted_message.hex()}\n")

    # Save the results to a binary file
    save_to_bin_file('encrypted_data.bin', encrypted_message, nonce, xmss_signature, measurement_results)

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