#pragma once

#ifndef __AES_NI_H__
#define __AES_NI_H__

#include <smmintrin.h>
#include <wmmintrin.h>
#include <cstdint>

class AES_128_CTR_ENC {
private:
    __m128i counter;
    __m128i roundKeys[11]{};

    static __m128i expandKey(__m128i key, __m128i generatedKey);

    void encryptFirst(__m128i& firstBlock);

public:
    AES_128_CTR_ENC(const __m128i& key, __m128i& iv, __m128i& firstBlock);

    void encrypt8Blocks(__m128i plaintextChunk[8]);

    void encrypt4Blocks(__m128i plaintextChunk[4]);

    void encrypt2Blocks(__m128i plaintextChunk[2]);

    void encrypt1Block(__m128i* plaintextChunk);
};

#endif