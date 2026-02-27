# botan

Botan (Japanese for peony flower) is a cryptography library released under the permissive Simplified BSD license.

Botan's goal is to be the best option for production cryptography by offering the tools necessary to implement a range of practical systems, such as TLSv1.3, X.509 PKI, modern AEAD ciphers, support for PKCS#11 and TPM hardware, memory-hard password hashing, and post quantum cryptography. All of this is covered by an extensive test suite, including an automated system for detecting side channels. The modular build system allows enabling or disabling features in a fine-grained way, and amalgamation builds are also supported.

## Original Repo

https://github.com/randombit/botan.git

## Notes

- Added a local `CMakeLists.txt` to drive `configure.py` and out-of-source builds.
- Pruned non-essential directories (tests, examples, tools) from this vendor copy.
- Removed files not relevant to the project.
