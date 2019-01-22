# skinny-rs
A Rust implemtation of the Skinny64 and Skinny128 block cipher. For more
information on Skinny see the 
[project website](https://sites.google.com/site/skinnycipher/).

The library provides functions to call all parameter sets of Skinny:

    Skinny64_64(plaintext, tweakey) -> ciphertext
    Skinny64_128(plaintext, tweakey) -> ciphertext
    Skinny64_192(plaintext, tweakey) -> ciphertext
    
    Skinny128_128(plaintext, tweakey) -> ciphertext
    Skinny128_256(plaintext, tweakey) -> ciphertext
    Skinny128_384(plaintext, tweakey) -> ciphertext



Implementation of the Skinny block cipher in Rust
