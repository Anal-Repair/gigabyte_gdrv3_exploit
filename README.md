# gigabyte_gdrv3_exploit
Rust program for interfacing with the gigabyte driver to gain access to powerful primitives such as arbitrary kernel memcpy.

The functions provided also allow to easily add other ioctls.
The checksum algorithm is implemented and 
the encryption algorithm(AES in cbc mode and yes the key really is GIGABYTEPASSWORD), 

which is required for a select few ioctls is also implemented. 
