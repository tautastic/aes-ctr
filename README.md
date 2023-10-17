# AES-CTR
AES-CTR implementation using AES-NI intrinsics and SIMD operations.

## Motivation
After reading [Understanding Cryptography, A Textbook for Students and Practitioners](https://www.crypto-textbook.com) by Christof Paar and Jan Pelzl, I tried to implement AES in C++. At the end of Chapter 4, the book says that it is possible to implement AES in such a way that it requires fewer than 4 CPU cycles to encrypt a byte. So, I gave it a shot.

## Performance (with I/O)

Below is the tabulated percentual differences between `openssl` and `tautastic/aes-ctr`:

| Metric                  | openssl Value       | tautastic/aes-ctr Value | Percentual Difference |
|-------------------------|---------------------|-------------------------|-----------------------|
| CPU Utilization         | 0.413               | 0.999                   | +141.89%              |
| Cycles                  | 2,183,036,314       | 932,415,861             | -57.29%               |
| Instructions            | 2,544,915,007       | 1,014,823,687           | -60.11%               |
| Cycles per Byte         | 5.4576              | 2.3310                  | -57.29%               |
| Throughput in GB/s      | 0.325               | 0.712                   | +119.08%              |

> **Note:** The comparison is done to illustrate the performance characteristics of `tautastic/aes-ctr` relative to `openssl`. Both libraries have their own set of features and optimizations which may suit different use cases.


#### openssl
```
Performance counter stats for 'openssl enc -aes-128-ctr -in song.webm -out song128.webm -K 2b7e151628aed2a6abf7158809cf4f3c -iv f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff':

            508,18 msec task-clock                       #    0,413 CPUs utilized             
               117      context-switches                 #  230,232 /sec                      
                 1      cpu-migrations                   #    1,968 /sec                      
               333      page-faults                      #  655,275 /sec                      
     2.183.036.314      cycles                           #    4,296 GHz                       
     2.544.915.007      instructions                     #    1,17  insn per cycle            
       416.065.929      branches                         #  818,732 M/sec                     
         3.988.395      branch-misses                    #    0,96% of all branches           

       1,230478489 seconds time elapsed

       0,129072000 seconds user
       0,380437000 seconds sys
```

#### tautastic/aes-ctr
```
Performance counter stats for 'aes-128-ctr -in song.webm -out song128.webm -K 2b7e151628aed2a6abf7158809cf4f3c -iv f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff':

            212,55 msec task-clock                       #    0,999 CPUs utilized             
                 0      context-switches                 #    0,000 /sec                      
                 0      cpu-migrations                   #    0,000 /sec                      
           103.563      page-faults                      #  487,245 K/sec                     
       932.415.861      cycles                           #    4,387 GHz                       
     1.014.823.687      instructions                     #    1,09  insn per cycle            
       129.065.235      branches                         #  607,229 M/sec                     
           550.080      branch-misses                    #    0,43% of all branches           

       0,212803631 seconds time elapsed

       0,087524000 seconds user
       0,124655000 seconds sys
```

> **Note:** The file `song.webm` has a size of `400MB`.

## Goals
Intel's whitepaper, "[Breakthrough AES Performance with Intel® AES New Instructions](https://www.intel.com/content/dam/develop/external/us/en/documents/10tb24-breakthrough-aes-performance-with-intel-aes-new-instructions-final-secure.pdf)", states in its conclusion: "We are able to achieve excellent AES performance on the Intel® Core™ i7 Processor Extreme Edition (i7-980X) using the new instructions. With optimized code, **it is possible to achieve ~0.24 cycles/byte on 6 cores for AES128** on parallel modes for large buffers."

So there is still plenty of room for further optimization.

## Disclaimer

This implementation is intended for academic purposes only and **should not be used in a production environment**.

## References
- [Understanding Cryptography, A Textbook for Students and Practitioners](https://www.crypto-textbook.com)

- [Breakthrough AES Performance with Intel® AES New Instructions](https://www.intel.com/content/dam/develop/external/us/en/documents/10tb24-breakthrough-aes-performance-with-intel-aes-new-instructions-final-secure.pdf)

- [Intel ® Advanced Encryption Standard (AES) New Instructions Set](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf)

- [NIST Recommendation for Block Cipher Modes of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
