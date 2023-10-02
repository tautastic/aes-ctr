#include "aes_ctr_enc.hpp"

AES_CTR::AES_CTR(const __m128i& key, __m128i& iv, __m128i& firstBlock) {
    this->counter = iv;
    this->roundKeys[0] = key;
    this->encryptFirst(firstBlock);
}

__m128i AES_CTR::expandKey(__m128i key, __m128i generatedKey) {
    generatedKey = _mm_shuffle_epi32(generatedKey, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, generatedKey);
}

void AES_CTR::encryptFirst(__m128i& firstBlock) {
    __m128i temp = _mm_xor_si128(this->counter, this->roundKeys[0]);

    this->roundKeys[1] = expandKey(this->roundKeys[0], _mm_aeskeygenassist_si128(this->roundKeys[0], 0x01));
    temp = _mm_aesenc_si128(temp, this->roundKeys[1]);

    this->roundKeys[2] = expandKey(this->roundKeys[1], _mm_aeskeygenassist_si128(this->roundKeys[1], 0x02));
    temp = _mm_aesenc_si128(temp, this->roundKeys[2]);

    this->roundKeys[3] = expandKey(this->roundKeys[2], _mm_aeskeygenassist_si128(this->roundKeys[2], 0x04));
    temp = _mm_aesenc_si128(temp, this->roundKeys[3]);

    this->roundKeys[4] = expandKey(this->roundKeys[3], _mm_aeskeygenassist_si128(this->roundKeys[3], 0x08));
    temp = _mm_aesenc_si128(temp, this->roundKeys[4]);

    this->roundKeys[5] = expandKey(this->roundKeys[4], _mm_aeskeygenassist_si128(this->roundKeys[4], 0x10));
    temp = _mm_aesenc_si128(temp, this->roundKeys[5]);

    this->roundKeys[6] = expandKey(this->roundKeys[5], _mm_aeskeygenassist_si128(this->roundKeys[5], 0x20));
    temp = _mm_aesenc_si128(temp, this->roundKeys[6]);

    this->roundKeys[7] = expandKey(this->roundKeys[6], _mm_aeskeygenassist_si128(this->roundKeys[6], 0x40));
    temp = _mm_aesenc_si128(temp, this->roundKeys[7]);

    this->roundKeys[8] = expandKey(this->roundKeys[7], _mm_aeskeygenassist_si128(this->roundKeys[7], 0x80));
    temp = _mm_aesenc_si128(temp, this->roundKeys[8]);

    this->roundKeys[9] = expandKey(this->roundKeys[8], _mm_aeskeygenassist_si128(this->roundKeys[8], 0x1B));
    temp = _mm_aesenc_si128(temp, this->roundKeys[9]);

    this->roundKeys[10] = expandKey(this->roundKeys[9], _mm_aeskeygenassist_si128(this->roundKeys[9], 0x36));
    temp = _mm_aesenclast_si128(temp, this->roundKeys[10]);

    firstBlock ^= temp;
    this->counter = _mm_shuffle_epi8(this->counter, _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f));
}

void AES_CTR::encrypt8Blocks(__m128i plaintextChunk[8]) {
    __m128i shuffle_mask = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
    __m128i temp1 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 1)), shuffle_mask), this->roundKeys[0]);
    __m128i temp2 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 2)), shuffle_mask), this->roundKeys[0]);
    __m128i temp3 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 3)), shuffle_mask), this->roundKeys[0]);
    __m128i temp4 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 4)), shuffle_mask), this->roundKeys[0]);
    __m128i temp5 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 5)), shuffle_mask), this->roundKeys[0]);
    __m128i temp6 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 6)), shuffle_mask), this->roundKeys[0]);
    __m128i temp7 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 7)), shuffle_mask), this->roundKeys[0]);
    this->counter = _mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 8));
    __m128i temp8 = _mm_xor_si128(_mm_shuffle_epi8(this->counter, shuffle_mask), this->roundKeys[0]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[1]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[1]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[1]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[1]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[1]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[1]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[1]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[1]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[2]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[2]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[2]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[2]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[2]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[2]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[2]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[2]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[3]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[3]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[3]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[3]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[3]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[3]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[3]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[3]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[4]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[4]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[4]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[4]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[4]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[4]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[4]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[4]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[5]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[5]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[5]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[5]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[5]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[5]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[5]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[5]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[6]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[6]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[6]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[6]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[6]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[6]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[6]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[6]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[7]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[7]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[7]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[7]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[7]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[7]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[7]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[7]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[8]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[8]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[8]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[8]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[8]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[8]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[8]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[8]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[9]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[9]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[9]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[9]);
    temp5 = _mm_aesenc_si128(temp5, this->roundKeys[9]);
    temp6 = _mm_aesenc_si128(temp6, this->roundKeys[9]);
    temp7 = _mm_aesenc_si128(temp7, this->roundKeys[9]);
    temp8 = _mm_aesenc_si128(temp8, this->roundKeys[9]);

    temp1 = _mm_aesenclast_si128(temp1, this->roundKeys[10]);
    temp2 = _mm_aesenclast_si128(temp2, this->roundKeys[10]);
    temp3 = _mm_aesenclast_si128(temp3, this->roundKeys[10]);
    temp4 = _mm_aesenclast_si128(temp4, this->roundKeys[10]);
    temp5 = _mm_aesenclast_si128(temp5, this->roundKeys[10]);
    temp6 = _mm_aesenclast_si128(temp6, this->roundKeys[10]);
    temp7 = _mm_aesenclast_si128(temp7, this->roundKeys[10]);
    temp8 = _mm_aesenclast_si128(temp8, this->roundKeys[10]);

    plaintextChunk[0] ^= temp1;
    plaintextChunk[1] ^= temp2;
    plaintextChunk[2] ^= temp3;
    plaintextChunk[3] ^= temp4;
    plaintextChunk[4] ^= temp5;
    plaintextChunk[5] ^= temp6;
    plaintextChunk[6] ^= temp7;
    plaintextChunk[7] ^= temp8;
}

void AES_CTR::encrypt4Blocks(__m128i plaintextChunk[4]) {
    __m128i shuffle_mask = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
    __m128i temp1 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 1)), shuffle_mask), this->roundKeys[0]);
    __m128i temp2 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 2)), shuffle_mask), this->roundKeys[0]);
    __m128i temp3 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 3)), shuffle_mask), this->roundKeys[0]);
    this->counter = _mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 4));
    __m128i temp4 = _mm_xor_si128(_mm_shuffle_epi8(this->counter, shuffle_mask), this->roundKeys[0]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[1]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[1]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[1]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[1]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[2]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[2]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[2]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[2]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[3]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[3]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[3]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[3]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[4]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[4]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[4]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[4]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[5]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[5]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[5]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[5]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[6]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[6]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[6]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[6]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[7]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[7]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[7]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[7]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[8]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[8]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[8]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[8]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[9]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[9]);
    temp3 = _mm_aesenc_si128(temp3, this->roundKeys[9]);
    temp4 = _mm_aesenc_si128(temp4, this->roundKeys[9]);
    temp1 = _mm_aesenclast_si128(temp1, this->roundKeys[10]);
    temp2 = _mm_aesenclast_si128(temp2, this->roundKeys[10]);
    temp3 = _mm_aesenclast_si128(temp3, this->roundKeys[10]);
    temp4 = _mm_aesenclast_si128(temp4, this->roundKeys[10]);

    plaintextChunk[0] ^= temp1;
    plaintextChunk[1] ^= temp2;
    plaintextChunk[2] ^= temp3;
    plaintextChunk[3] ^= temp4;
}

void AES_CTR::encrypt2Blocks(__m128i plaintextChunk[2]) {
    __m128i shuffle_mask = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
    __m128i temp1 = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 1)), shuffle_mask), this->roundKeys[0]);
    this->counter = _mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 2));
    __m128i temp2 = _mm_xor_si128(_mm_shuffle_epi8(this->counter, shuffle_mask), this->roundKeys[0]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[1]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[1]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[2]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[2]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[3]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[3]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[4]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[4]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[5]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[5]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[6]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[6]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[7]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[7]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[8]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[8]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[9]);
    temp2 = _mm_aesenc_si128(temp2, this->roundKeys[9]);
    temp1 = _mm_aesenclast_si128(temp1, this->roundKeys[10]);
    temp2 = _mm_aesenclast_si128(temp2, this->roundKeys[10]);

    plaintextChunk[0] ^= temp1;
    plaintextChunk[1] ^= temp2;
}

void AES_CTR::encrypt1Block(__m128i* plaintextChunk) {
    __m128i shuffle_mask = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
    this->counter = _mm_add_epi64(this->counter, _mm_set_epi32(0, 0, 0, 1));
    __m128i temp1 = _mm_xor_si128(_mm_shuffle_epi8(this->counter, shuffle_mask), this->roundKeys[0]);

    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[1]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[2]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[3]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[4]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[5]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[6]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[7]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[8]);
    temp1 = _mm_aesenc_si128(temp1, this->roundKeys[9]);
    temp1 = _mm_aesenclast_si128(temp1, this->roundKeys[10]);

    plaintextChunk[0] ^= temp1;
}
