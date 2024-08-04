# Secure SDLC System
## Description
This project implements a secure Software Development Life Cycle (SDLC) system with role-based access control and encryption for data communication and storage during different phases of the SDLC.
## Phases
1. **Requirements Phase**: Uses AES-256 encryption for medium to high sensitivity data.
2. **Design Phase**: Uses RSA-2048 encryption for medium sensitivity data.
3. **Implementation Phase**: Uses ECC with Curve25519 encryption for high sensitivity data.
4. **Testing Phase**: Uses AES-128 encryption for medium sensitivity data.
5. **Deployment Phase**: Uses RSA-4096 encryption for high sensitivity data.
6. **Maintenance Phase**: Uses AES-192 encryption for medium sensitivity data.
## Role-Based Access Control
- **Project Manager**: Full access to all phases.
- **Developer**: Can read, write, and update in the implementation phase; can read and write in the testing phase.
- **QA Engineer**: Can read, write, and update in the testing phase.
- **Admin**: Full access to all phases, including delete.
## Usage
1. **Authentication**: Users must authenticate with their username and password.
2. **Phase Access**: Users can select the SDLC phase they want to access.
3. **Actions**: Users can perform actions (read, write, delete, update) based on their role's permissions.
4. **Encryption/Decryption**: Data is encrypted before storage and decrypted upon access using phase-specific encryption algorithms.

## Example Commands
**Note** getpass() does not work with all IDE environment for example in pycharm using virtual environment, therefore, may change the IDE environment or replace `getpass()` with `input()`
- **Read Data**: Reads and decrypts data from a specified file in the selected phase.
- **Write Data**: Encrypts and writes data to a specified file in the selected phase.
- **Delete Data**: Deletes a specified file in the selected phase.
- **Update Data**: Encrypts and updates data in a specified file in the selected phase.
## Running the Program
To run the program, use the following command:
Follow the prompts for username, password, phase selection, action, passphrase, and filename.
### Testing
Use the provided testing data for each phase to test the functionality. Ensure users' actions align with their role-based permissions.
