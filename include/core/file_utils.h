#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <vector>
#include <cstdint>

class FileUtils {
public:
    static std::vector<unsigned char> readBinaryFile(const std::string& filename);
    static std::string readTextFile(const std::string& filename);
    static void saveBinaryFile(const std::string& filename, const std::vector<unsigned char>& data);
    static void saveEncryptedToFile(const std::string& filename, const std::vector<uint64_t>& encrypted);
    static std::vector<uint64_t> readEncryptedFile(const std::string& filename);
    static bool fileExists(const std::string& filename);
    static void createFile(const std::string& filename);
    static std::string bytesToHex(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> hexToBytes(const std::string& hex);
};

#endif // FILE_UTILS_H
