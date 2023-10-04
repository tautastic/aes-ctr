#include <iostream>
#include <string>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common_io.hpp"
#include "aes_256_ctr.hpp"

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
            AES_EXTRACT_8_BLOCKS(input_data, output_data, offset);
            aes_ctr.encrypt8Blocks(reinterpret_cast<__m128i*>(output_data + offset));
            offset += 128;
        } else if (remaining >= 64) {
            AES_EXTRACT_4_BLOCKS(input_data, output_data, offset);
            aes_ctr.encrypt4Blocks(reinterpret_cast<__m128i*>(output_data + offset));
            offset += 64;
        } else if (remaining >= 32) {
            AES_EXTRACT_2_BLOCKS(input_data, output_data, offset);
            aes_ctr.encrypt2Blocks(reinterpret_cast<__m128i*>(output_data + offset));
            offset += 32;
        } else {
            AES_EXTRACT_1_BLOCK(input_data, output_data, offset);
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
