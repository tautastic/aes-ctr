#include <iostream>
#include <string>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aes_256_ctr_enc.hpp"

void hex_to_bytes(const std::string& hex, unsigned char* bytes) {
    for (size_t i = 0, j = 0; i < hex.length(); i += 2, ++j) {
        bytes[j] = static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
}

bool verify_and_open_files(int& input_fd, int& output_fd, const std::string& input_file, const std::string& output_file) {
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

int main(int argc, char* argv[]) {
    std::string input_file, output_file;
    unsigned char key_bytes[32], iv_bytes[16];
    __m128i keyLower, keyUpper, iv;
    bool iv_provided = false, input_file_provided = false, output_file_provided = false, key_provided = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-in") {
            input_file = argv[++i];
            input_file_provided = true;
        } else if (arg == "-out") {
            output_file = argv[++i];
            output_file_provided = true;
        } else if (arg == "-K") {
            hex_to_bytes(argv[++i], key_bytes);
            keyLower = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key_bytes));
            keyUpper = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key_bytes + 16));
            key_provided = true;
        } else if (arg == "-iv") {
            hex_to_bytes(argv[++i], iv_bytes);
            iv = _mm_loadu_si128(reinterpret_cast<const __m128i*>(iv_bytes));
            iv_provided = true;
        }
    }

    if (!input_file_provided || !output_file_provided || !key_provided || !iv_provided) {
        std::cerr << "Error: Missing required arguments.\n";
        return 1;
    }

    int input_fd, output_fd;
    if (!verify_and_open_files(input_fd, output_fd, input_file, output_file)) {
        return 1;
    }

    struct stat sb{};
    if (fstat(input_fd, &sb) == -1) {
        std::cerr << "Error: Could not retrieve file statistics.\n";
        return 1;
    }
    size_t file_size = sb.st_size;

    auto input_data = static_cast<unsigned char*>(mmap(NULL, file_size, PROT_READ, MAP_SHARED, input_fd, 0));
    auto output_data = static_cast<unsigned char*>(mmap(NULL, file_size, PROT_WRITE, MAP_SHARED, output_fd, 0));
    if (input_data == MAP_FAILED || output_data == MAP_FAILED) {
        std::cerr << "Error: Memory mapping failed.\n";
        return 1;
    }

    if (ftruncate(output_fd, file_size) == -1) {
        std::cerr << "Error: Could not truncate output file.\n";
        return 1;
    }

    auto firstBlock = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data));
    AES_256_CTR_ENC aes_ctr(keyLower, keyUpper, iv, firstBlock);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data), firstBlock);

    for (size_t offset = 16; offset < file_size;) {
        size_t remaining = file_size - offset;
        if (remaining >= 128) {
            // Copy 8 blocks (128 bytes)
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 16),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 16)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 32),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 32)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 48),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 48)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 64),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 64)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 80),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 80)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 96),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 96)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 112),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 112)));
            aes_ctr.encrypt8Blocks(reinterpret_cast<__m128i*>(output_data + offset));
            offset += 128;
        } else if (remaining >= 64) {
            // Copy 4 blocks (64 bytes)
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 16),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 16)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 32),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 32)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 48),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 48)));
            aes_ctr.encrypt4Blocks(reinterpret_cast<__m128i*>(output_data + offset));
            offset += 64;
        } else if (remaining >= 32) {
            // Copy 2 blocks (32 bytes)
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset + 16),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset + 16)));
            aes_ctr.encrypt2Blocks(reinterpret_cast<__m128i*>(output_data + offset));
            offset += 32;
        } else {
            // Copy 1 block (16 bytes)
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output_data + offset),_mm_loadu_si128(reinterpret_cast<const __m128i*>(input_data + offset)));
            aes_ctr.encrypt1Block(reinterpret_cast<__m128i*>(output_data + offset));
            offset += 16;
        }
    }

    if (munmap(input_data, file_size) == -1 || munmap(output_data, file_size) == -1) {
        std::cerr << "Error: Could not unmap memory.\n";
        return 1;
    }

    if (close(input_fd) == -1 || close(output_fd) == -1) {
        std::cerr << "Error: Could not close file descriptor.\n";
        return 1;
    }

    return 0;
}
