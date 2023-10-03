#pragma once

#ifndef __AES_NI_H__
#define __AES_NI_H__

#include <cstdint>
#include <immintrin.h>

#define MM_SHUFFLE_PD(a,b,c) (__m128i) _mm_shuffle_pd((__m128d) a, (__m128d) b, c)

class AES_192_CTR_ENC {
private:
    __m128i counter;
    __m128i roundKeys[13]{};

    static void expandKey(__m128i& temp1, __m128i temp2, __m128i& temp3);

    void encryptFirst(__m128i& firstBlock);

public:
    AES_192_CTR_ENC(const __m128i& keyLower, const __m128i& keyUpper, __m128i& iv, __m128i& firstBlock);

    void encrypt8Blocks(__m128i plaintextChunk[8]);

    void encrypt4Blocks(__m128i plaintextChunk[4]);

    void encrypt2Blocks(__m128i plaintextChunk[2]);

    void encrypt1Block(__m128i* plaintextChunk);

};

#endif