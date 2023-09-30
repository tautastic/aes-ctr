# AES-CTR
AES-CTR implementation using AES-NI intrinsics and SIMD operations.

## Motivation
After reading [Understanding Cryptography, A Textbook for Students and Practitioners](https://www.crypto-textbook.com) by Christof Paar and Jan Pelzl, I tried to implement AES in C++. At the end of Chapter 4, the book says that it is possible to implement AES in such a way that it requires fewer than 4 CPU cycles to encrypt a byte. So, I gave it a shot.

## Current State
I am still uncertain how to measure performance as precisely as possible, but for now, I am running a large amount of data through the encryption process and using `perf stat`.

Currently, for a data size of `5.12GB`, the `perf stat` output is:
```
 Performance counter stats for './aes_ctr':

            802,79 msec task-clock                       #    0,999 CPUs utilized             
                 3      context-switches                 #    3,737 /sec                      
                 1      cpu-migrations                   #    1,246 /sec                      
               130      page-faults                      #  161,935 /sec                      
     3.499.639.621      cycles                           #    4,359 GHz                       
     5.166.008.769      instructions                     #    1,48  insn per cycle            
       111.130.909      branches                         #  138,431 M/sec                     
            31.385      branch-misses                    #    0,03% of all branches           

       0,803203936 seconds time elapsed

       0,799339000 seconds user
       0,003327000 seconds sys
```

This results in `0.683 cycles/byte` and a throughput of `6.37GB/s`. The results are achieved on 1 core and 1 thread.

## Goals
Intel's whitepaper [Breakthrough AES Performance with Intel® AES New Instructions](https://www.intel.com/content/dam/develop/external/us/en/documents/10tb24-breakthrough-aes-performance-with-intel-aes-new-instructions-final-secure.pdf) states in its conclusion, "We are able to achieve excellent AES performance on the Intel® Core™ i7 Processor Extreme Edition, i7-980X, using the new instructions. With optimized code, **it is possible to achieve ~0.24 cycles/byte on 6 cores for AES128** on parallel modes for large buffers."

So my next goals are:
- [ ] Ensure that my measurements are accurate.
- [ ] Implement further optimizations.
- [ ] Reach `0.23 cycles/byte`, as `0.23 < 0.24`.
- [ ] Write a new and improved whitepaper.
- [ ] Win the Nobel Prize.
