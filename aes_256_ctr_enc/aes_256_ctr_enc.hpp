#pragma once

#ifndef __AES_NI_H__
#define __AES_NI_H__

#include <cstdint>
#include <immintrin.h>


class AES_256_CTR_ENC {
private:
    __m128i counter;
    __m128i roundKeys[15]{};

    static __m128i expandKey1(__m128i key, __m128i generatedKey);

    static __m128i expandKey2(__m128i key, __m128i generatedKey);

    void encryptFirst(__m128i& firstBlock);

public:
    AES_256_CTR_ENC(const __m128i& keyLower, const __m128i& keyUpper, __m128i& iv, __m128i& firstBlock);

    void encrypt8Blocks(__m128i plaintextChunk[8]);

    void encrypt4Blocks(__m128i plaintextChunk[4]);

    void encrypt2Blocks(__m128i plaintextChunk[2]);

    void encrypt1Block(__m128i* plaintextChunk);
};

#endif