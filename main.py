import base64
import getpass
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Protocol.KDF import scrypt
from collections import defaultdict

# User data for authentication and roles
USERS = {
    'manager': {'password': 'managerpass', 'role': 'project_manager'},
    'dev1': {'password': 'dev1pass', 'role': 'developer'},
    'qa1': {'password': 'qa1pass', 'role': 'qa_engineer'},
    'admin': {'password': 'adminpass', 'role': 'admin'},
}

# Role-based access control with specific actions
ACCESS_CONTROL = {
    'project_manager': {
        'requirements': ['read', 'write', 'update'],
        'design': ['read', 'write', 'update'],
        'implementation': ['read', 'write', 'update'],
        'testing': ['read', 'write', 'update'],
        'deployment': ['read', 'write', 'update'],
        'maintenance': ['read', 'write', 'update'],
    },
    'developer': {
        'implementation': ['read', 'write', 'update'],
        'testing': ['read', 'write'],
    },
    'qa_engineer': {
        'testing': ['read', 'write', 'update'],
    },
    'admin': {
        'requirements': ['read', 'write', 'update', 'delete'],
        'design': ['read', 'write', 'update', 'delete'],
        'implementation': ['read', 'write', 'update', 'delete'],
        'testing': ['read', 'write', 'update', 'delete'],
        'deployment': ['read', 'write', 'update', 'delete'],
        'maintenance': ['read', 'write', 'update', 'delete'],
    },
}

# Simulated storage for each phase's data
DATA_STORAGE = {
    'requirements': {
        'requirements.txt': 'Project objectives: ...\nFunctional requirements: ...\nNon-functional requirements: ...'
    },
    'design': {
        'architecture.pdf': 'Architecture diagrams and design specifications...'
    },
    'implementation': {
        'source_code.py': 'print("Hello, World!")\n# More source code...',
        'config.cfg': 'configuration settings...'
    },
    'testing': {
        'test_cases.xlsx': 'Test case 1: ...\nTest case 2: ...'
    },
    'deployment': {
        'deployment_script.sh': '#!/bin/bash\n# Deployment script...'
    },
    'maintenance': {
        'patch_notes.txt': 'Patch version 1.0.1: ...\nPatch version 1.0.2: ...'
    }
}


def authenticate_user(username, password):
    user = USERS.get(username)
    if user and user['password'] == password:
        return user['role']
    return None


def check_access(role, phase, action):
    return action in ACCESS_CONTROL.get(role, {}).get(phase, [])


def derive_key(passphrase, salt, key_length=32):
    return scrypt(passphrase.encode(), salt.encode(), key_length, N=2 ** 14, r=8, p=1)


def save_data(phase, filename, data):
    DATA_STORAGE[phase][filename] = data


def read_data(phase, filename):
    return DATA_STORAGE[phase].get(filename)


def delete_data(phase, filename):
    if filename in DATA_STORAGE[phase]:
        del DATA_STORAGE[phase][filename]
        return True
    return False


# Define classes for each phase
class RequirementsPhase:
    def __init__(self, key):
        self.key = key[:32]  # 256 bits

    def encrypt_data(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        data = base64.b64decode(encrypted_data)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode()


class DesignPhase:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def encrypt_data(self, data):
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_data = cipher.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        data = base64.b64decode(encrypted_data)
        cipher = PKCS1_OAEP.new(self.key)
        decrypted_data = cipher.decrypt(data)
        return decrypted_data.decode()


class ImplementationPhase:
    def __init__(self):
        self.key = ECC.generate(curve='P-256')
        self.public_key = self.key.public_key()

    def encrypt_data(self, data):
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_data = cipher.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        data = base64.b64decode(encrypted_data)
        cipher = PKCS1_OAEP.new(self.key)
        decrypted_data = cipher.decrypt(data)
        return decrypted_data.decode()


class TestingPhase:
    def __init__(self, key):
        self.key = key[:16]  # 128 bits

    def encrypt_data(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        data = base64.b64decode(encrypted_data)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode()


class DeploymentPhase:
    def __init__(self):
        self.key = RSA.generate(4096)
        self.public_key = self.key.publickey()

    def encrypt_data(self, data):
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_data = cipher.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        data = base64.b64decode(encrypted_data)
        cipher = PKCS1_OAEP.new(self.key)
        decrypted_data = cipher.decrypt(data)
        return decrypted_data.decode()


class MaintenancePhase:
    def __init__(self, key):
        self.key = key[:24]  # 192 bits

    def encrypt_data(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        data = base64.b64decode(encrypted_data)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode()


def main():
    print("Welcome to the Secure SDLC System")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    role = authenticate_user(username, password)
    if not role:
        print("Authentication failed. Exiting.")
        return

    print(f"Welcome, {username}!")
    phases = {
        'requirements': RequirementsPhase,
        'design': DesignPhase,
        'implementation': ImplementationPhase,
        'testing': TestingPhase,
        'deployment': DeploymentPhase,
        'maintenance': MaintenancePhase,
    }

    while True:
        print("\nBelow are your accessible SDLC Phases: ")
        for phase in ACCESS_CONTROL[role]:
            print(phase)
        phase = input("Enter the SDLC phase you want to access (or 'exit' to quit): ").lower()
        if phase == 'exit':
            break

        if phase not in phases:
            print("Invalid phase. Please try again.")
            continue

        action = input(f"Enter action (read/write/delete/update) for {phase} phase: ").lower()
        if not check_access(role, phase, action):
            print(f"You do not have permission to perform {action} on {phase} phase.")
            continue

        passphrase = input(f"Enter the passphrase for {phase} phase: ")
        salt = phase  # Using phase name as salt for simplicity

        if phase in ['requirements', 'testing', 'maintenance']:
            key = derive_key(passphrase, salt)
            phase_instance = phases[phase](key)
        else:
            phase_instance = phases[phase]()

        filename = input("Enter the filename: ")

        if action == 'read':
            encrypted_data = read_data(phase, filename)
            if encrypted_data:
                decrypted_data = phase_instance.decrypt_data(encrypted_data)
                print("Decrypted data:", decrypted_data)
            else:
                print("File not found.")
        elif action == 'write':
            data = input("Enter data to write: ")
            encrypted_data = phase_instance.encrypt_data(data)
            save_data(phase, filename, encrypted_data)
            print("Data written successfully.")
        elif action == 'delete':
            if delete_data(phase, filename):
                print("File deleted successfully.")
            else:
                print("File not found.")
        elif action == 'update':
            data = input("Enter new data: ")
            encrypted_data = phase_instance.encrypt_data(data)
            save_data(phase, filename, encrypted_data)
            print("Data updated successfully.")
        else:
            print("Invalid action.")


if __name__ == "__main__":
    main()
