[![license](https://img.shields.io/github/license/lfalck/AzureFunctionsPGPEncrypt.svg)]()
# AzureFunctionsPGPEncryptDecrypt

Azure function which performs PGP encryption and decryption using [PgpCore](https://github.com/mattosaurus/PgpCore). The private and public key can be stored in an environment variable or in Azure Key Vault by using [Key Vault references](https://docs.microsoft.com/en-us/azure/app-service/app-service-key-vault-references).

## Encrypt
* Use the function PGPEncrypt.
* Store a Base64 encoded public key or a Key Vault reference in an environment variable called pgp-public-key.
* Make a request to the function with the unencrypted data in the body.

## Decrypt
* Use the function PGPDecrypt.
* Store a Base64 encoded private key or a Key Vault reference in an environment variable called pgp-private-key.
* Store a passphrase or a Key Vault reference in an environment variable called pgp-passphrase (optional).
* Make a request to the function with the encrypted data in the body.


## Key generation
* Option 1: Use a program such as [GPG](https://gnupg.org/) or [GPW4Win](https://www.gpg4win.org/).  
* Option 2: Use the console app **PGPEncryptConsoleApp** in the repo.
