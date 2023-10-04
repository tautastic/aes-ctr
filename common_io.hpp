#pragma once

#define AES_EXTRACT_8_BLOCKS(in, out, offset) do { \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 16),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 16))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 32),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 32))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 48),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 48))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 64),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 64))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 80),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 80))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 96),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 96))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 112),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 112))); \
} while (0)

#define AES_EXTRACT_4_BLOCKS(in, out, offset) do { \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 16),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 16))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 32),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 32))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 48),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 48))); \
} while (0)

#define AES_EXTRACT_2_BLOCKS(in, out, offset) do { \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset))); \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset + 16),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset + 16))); \
} while (0)

#define AES_EXTRACT_1_BLOCK(in, out, offset) do { \
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + offset),_mm_loadu_si128(reinterpret_cast<const __m128i*>(in + offset))); \
} while (0)

static inline void hex_to_bytes(const std::string& hex, unsigned char* bytes) {
    for (size_t i = 0, j = 0; i < hex.length(); i += 2, ++j) {
        bytes[j] = static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
}

static inline bool verify_and_open_files(int& input_fd, int& output_fd, const std::string& input_file, const std::string& output_file) {
    input_fd = open(input_file.c_str(), O_RDONLY);
    if (input_fd < 0) {
        std::cerr << "Error: Could not open input file.\n";
        return false;
    }

    output_fd = open(output_file.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (output_fd < 0) {
        std::cerr << "Error: Could not open or create output file.\n";
        return false;
    }

    return true;
}