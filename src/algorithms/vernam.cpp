#include "/home/vikct/EncryptionAlgorithmRGR/include/algorithms/vernam.h"
#include "/home/vikct/EncryptionAlgorithmRGR/include/core/file_utils.h"
#include <iostream>
#include <random>
#include <functional>
#include <iomanip>
 
std::string VernamAlgorithm::getName() const {
    return "Vernam Cipher";
}

std::string VernamAlgorithm::getKey() const {
    return "Vernam Cipher использует ключ, сгенерированный из пароля";
}

std::vector<unsigned char> VernamAlgorithm::hexToBytes(const std::string& hex) const {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Неверная длина 16-ричной строки (должна быть четной)");
    }

    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string VernamAlgorithm::bytesToHex(const std::vector<unsigned char>& data) const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string VernamAlgorithm::generateKeyFromPassword(const std::string& password, size_t requiredLength) const {
    size_t seed = std::hash<std::string>{}(password);
    std::mt19937 gen(seed);
    std::uniform_int_distribution<unsigned char> dist(0, 255);
    
    std::string key;
    key.reserve(requiredLength);
    
    for (size_t i = 0; i < requiredLength; ++i) {
        key += static_cast<char>(dist(gen));
    }
    
    return key;
}

std::string VernamAlgorithm::encryptText(const std::string& text) {
    std::cout << "Введите пароль: ";
    std::string password;
    std::getline(std::cin, password);
    
    std::string key = generateKeyFromPassword(password, text.length());
    
    std::vector<unsigned char> ciphertext;
    ciphertext.reserve(text.length());
    
    for (size_t i = 0; i < text.length(); ++i) {
        ciphertext.push_back(text[i] ^ key[i]);
    }
    
    return FileUtils::bytesToHex(ciphertext);
}

std::string VernamAlgorithm::decryptText(const std::string& ciphertext) {
    try {
        
        std::vector<unsigned char> cipherBytes = FileUtils::hexToBytes(ciphertext);
        
        std::cout << "Введите пароль: ";
        std::string password;
        std::getline(std::cin, password);
        
        std::string key = generateKeyFromPassword(password, cipherBytes.size());
        
        std::string plaintext;
        plaintext.reserve(cipherBytes.size());
        
        for (size_t i = 0; i < cipherBytes.size(); ++i) {
            plaintext += cipherBytes[i] ^ key[i];
        }
        
        return plaintext;
    } catch (const std::exception& e) {
        throw std::runtime_error("Ошибка при дешифровании: неверный формат hex строки");
    }
}

void VernamAlgorithm::encryptFile(const std::string& inputPath, const std::string& outputPath) {
    auto content = FileUtils::readTextFile(inputPath);
    
    std::cout << "Введите пароль: ";
    std::string password;
    std::getline(std::cin, password);
    
    std::string key = generateKeyFromPassword(password, content.length());
    std::vector<unsigned char> ciphertext;
    ciphertext.reserve(content.length());
    
    for (size_t i = 0; i < content.length(); ++i) {
        ciphertext.push_back(content[i] ^ key[i]);
    }
    

    std::string hexData = FileUtils::bytesToHex(ciphertext);
    FileUtils::saveBinaryFile(outputPath, 
                            std::vector<unsigned char>(ciphertext.begin(), ciphertext.end()));
}

void VernamAlgorithm::decryptFile(const std::string& inputPath, const std::string& outputPath) {
    auto ciphertext = FileUtils::readBinaryFile(inputPath);
    
    std::cout << "Введите пароль: ";
    std::string password;
    std::getline(std::cin, password);
    
    std::string key = generateKeyFromPassword(password, ciphertext.size());
    std::string plaintext;
    plaintext.reserve(ciphertext.size());
    
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        plaintext += ciphertext[i] ^ key[i];
    }
    
    FileUtils::saveBinaryFile(outputPath, 
                            std::vector<unsigned char>(plaintext.begin(), plaintext.end()));
}


extern "C" {
    IEncryptionAlgorithm* createAlgorithm() {
        return new VernamAlgorithm();
    }
    
    void destroyAlgorithm(IEncryptionAlgorithm* p) {
        delete p;
    }
}
