# Crypto

Crypto is a Java package that offers a comprehensive suite of functionalities for encoding and decoding messages using various cryptographic techniques. The main functionalities include Caesar cipher, XOR, Vigenere cipher, One-Time Pad, and CBC (Cipher Block Chaining). The package is designed to facilitate educational and practical applications of cryptographic concepts.

## Features

- **Encoding and Decoding**: Support for multiple encoding and decoding methods including Caesar cipher, XOR, Vigenere cipher, One-Time Pad, and CBC.
- **Brute Force Decoding**: Functions to perform brute force decoding for Caesar and XOR ciphers.
- **Frequency Analysis**: Tools for frequency analysis in decoding, particularly useful for breaking Caesar and Vigenere ciphers.
- **Key-Length Search**: Functionality to determine the key length in Vigenere cipher.
- **CBC with Encryption**: Implements Cipher Block Chaining (CBC) mode of operation.
- **Shell Interface**: A bonus feature providing a command-line interface for the encryption and decryption operations.

## Structure

The package is divided into three main classes:

1. **Main Class**: The entry point of the application, showcasing the usage of various encryption and decryption methods.
2. **Encrypt Class**: Contains methods for encrypting messages using different cryptographic algorithms.
3. **Decrypt Class**: Offers a set of methods for decrypting messages and breaking ciphers using techniques like brute force, frequency analysis, and key-length search.

## Usage

1. **Main Class**: 
   - Compile and run the `Main` class.
   - Follow the on-screen instructions to choose the encryption/decryption method.
   - Input the message and key (if required) when prompted.
   
2. **Encrypt Class**:
   - Use the `encrypt` method to encrypt a message by specifying the message, key, and the type of encryption.
   - Supported encryption types are: CAESAR, VIGENERE, XOR, ONETIME, and CBC.
   
3. **Decrypt Class**:
   - Use the `breakCipher` method to decrypt a message by specifying the cipher text and the type of decryption.
   - Supported decryption types are: CAESAR, VIGENERE, and XOR.
   - Additional methods like `caesarWithFrequencies` and `vigenereWithFrequencies` are available for frequency analysis-based decryption.
   
## Dependencies

- The package requires Java SE Development Kit 8 (JDK 8) or later.