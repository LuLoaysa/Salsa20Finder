# Salsa20Finder
Finding Salsa20 keys in memory

Please note that stream ciphers encryption keys can be found in memory while encrypting or decrypting data.

This script is part of my dissertation that successfully found Salsa20 keys in memory to decrypt files encrypted by ransomware, specifically Sodinokibi or REvil. The script reads binary files which are extracted from memory dumps. The files can be in the format of .vmem, .core, .dmp, etc.

While reading the file it finds the key, nonce pairs and counts them showing them to the user. It also outputs them to a text file.
