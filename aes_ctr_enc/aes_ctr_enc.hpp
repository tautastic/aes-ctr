#pragma once

#ifndef __AES_NI_H__
#define __AES_NI_H__

#include <smmintrin.h>
#include <wmmintrin.h>
#include <cstdint>

class AES_CTR {
private:
    __m128i counter;
    __m128i roundKeys[11]{};

    static __m128i expandKey(__m128i key, __m128i generatedKey);

    void encryptFirst(__m128i& firstBlock);

public:
    AES_CTR(const __m128i& key, __m128i& iv, __m128i& firstBlock);

    void encrypt4Blocks(__m128i* plaintextChunk);

    void encrypt3Blocks(__m128i* plaintextChunk);

    void encrypt2Blocks(__m128i* plaintextChunk);

    void encrypt1Block(__m128i* plaintextChunk);
};

#endif