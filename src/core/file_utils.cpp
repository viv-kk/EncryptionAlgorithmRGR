#include "/home/vikct/EncryptionAlgorithmRGR/include/core/file_utils.h"
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <cstdint>
std::vector<unsigned char> FileUtils::readBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл " + filename);
    }
   
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();
    
    return buffer;
}


std::string FileUtils::readTextFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл " + filename);
    }
    
    return std::string((std::istreambuf_iterator<char>(file)), 
                      std::istreambuf_iterator<char>());
}

void FileUtils::saveBinaryFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось создать файл " + filename);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

void FileUtils::saveEncryptedToFile(const std::string& filename, const std::vector<uint64_t>& encrypted) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось создать файл " + filename);
    }
    file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size() * sizeof(uint64_t));
    file.close();
}

std::vector<uint64_t> FileUtils::readEncryptedFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл " + filename);
    }
    
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (fileSize % sizeof(uint64_t) != 0) {
        throw std::runtime_error("Некорректный размер зашифрованного файла");
    }
    
    std::vector<uint64_t> encrypted(fileSize / sizeof(uint64_t));
    file.read(reinterpret_cast<char*>(encrypted.data()), fileSize);
    file.close();
    
    return encrypted;
}

bool FileUtils::fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

void FileUtils::createFile(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось создать файл " + filename);
    }
    std::cout << "Введите содержимое файла (завершите ввод пустой строкой):\n";
    std::string line;
    while (std::getline(std::cin, line) && !line.empty()) {
        file << line << std::endl;
    }
    file.close();
}
