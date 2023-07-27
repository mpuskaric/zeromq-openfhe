# zeromq-openfhe

Client-Server with homomorphic encryption algorithms implemented. Client generates cryptocontext, 
key pair and evaluation multiplication key. Server receives the encrypted vector and performs 
simple processing, i.e. homomorphic multiplication of two vectors. Server then sends the result 
back to client for decryption

Prerequisites: OpenFHE[1], libzmq, cppzmq

[1] https://github.com/openfheorg/openfhe-development

## Build instructions
```
mkdir build
cd build
cmake ..
make
```
