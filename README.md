# GOST block cipher
This is a simple C implementation of the GOST block cipher as specified in https://en.wikipedia.org/wiki/GOST_(block_cipher). This is only for educational purposes don't use it for anything serious. 

# Usage
To build and run the test simply run
```bash
make && ./test
```

To use the cipher in other code include the `gost.h` header and compile with `gcc <your-binary> gost.c <your-options>`

