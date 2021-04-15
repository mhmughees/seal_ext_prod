# External Product
This repository contains code for homomorphic **product** between two Lattice based homomorphic encryptions schemes. Namely, **RGSW** and **BFV**. In crypto literature this operation is reffered as an **external product**. 

The advantage of **external product** over normal product is that the noise growth is *additive*. While, the noise growth due to normal product is *multiplicative*. Further information on Noise management in *lattice* based homomorphic encryption schemes can be found here [1]. Note **RGSW** should encrypt plaintext with small norm `{0,1}` to have *additive* noise growth.  

Due to additive increase in the noise, **external product** are suitable for homomorphically compute *deeper* circuits without using any advance techniques such as **bootstrapping**, **key switching*** and **relinearization**.

Additive noise growth also allow smaller ciphertext **expansion factor**, that improves the bandwidth overhead. 

## Implementation details

- Our implementation is based on Microsoft Seal and NFLlib. Specifically, we have utilized CRT variant of **BFV** scheme that is implemented in Microsoft Seal. Due to CRT, our implementation could handle coefficient modulus of 124 bits. 
- We have implemented **RGSW** encryption schemes within Microsoft Seal from scratch and only used few helper functions to manage polynomials. 
- Even thought Microsoft Seal provides NTT based polynomial multiplications which has a complexity of *O(n log n)*. But we found Microsoft Seal's implementation of polynomial multiplications at least 3x slower than similar libraries such as TFHE. Therefore, we further integrated **NFLlib** polynomial mutiplications within Microsoft seal. **NFLlib** is an efficient C++ library specialized in polynomial rings operations. It uses several programming optimization techniques (SSE and AVX2 specializations) to provide efficient polynomial operations. 

## Compilation

- First install [Microsoft Seal version 3.5.1](https://github.com/microsoft/SEAL/tree/3.5.1) 
- And then install [NFLlib](https://github.com/micciancio/NFLlib) 
- Make sure these libraries are properly installed in `/usr/local/lib` 
- Then compile this code using `cmake` with these cmake options `-DCMAKE_BUILD_TYPE=Release -DNFL_OPTIMIZED=ON -DSEAL_USE_ZLIB=OFF  -DSEAL_USE_MSGSL=OFF`
- Then just run `./cmake-build-debug/external_prod ` this will run `test_external_prod` example given in `main.cpp` file

## Code explaination
- This implementation sets `q=2^{124}, n=4096, t=2^{62}`, where q= coefficient mod, n= polynomial degree, t= plaintext mod. These parameters allow expansion factor of 4 only. 
-   
- There are two tests in the `main.cpp`:  `test_external_prod_chain` and `test_external_prod`.
- `test_external_prod` performs external product between **RGSW** and **BFV** ciphertexts. Specifically, it highlights the effect of **RGSW** ct size vs noise budget after the product. Expected behaviour is that as size of **RGSW** ct increases, noise budget should also increase. 
- `test_external_prod_chain` performs multiple external producsts in sequence. This test shows that external products could be used to evaluate much deeper circuits.
