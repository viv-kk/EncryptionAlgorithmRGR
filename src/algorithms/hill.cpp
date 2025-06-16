#include "/home/vikct/EncryptionAlgorithmRGR/include/algorithms/hill.h"
#include "/home/vikct/EncryptionAlgorithmRGR/include/core/file_utils.h"
#include <iostream>
#include <random>
#include <stdexcept>
#include <tuple>
#include <sstream>
#include <iomanip>
 
HillAlgorithm::HillAlgorithm() {
    generateKey();
}

std::string HillAlgorithm::getKey() const {
    std::stringstream ss;
    ss << "Ключ-матрица:\n"
       << key[0][0] << " " << key[0][1] << "\n"
       << key[1][0] << " " << key[1][1] << "\n\n"
       << "Обратный ключ-матрица:\n"
       << inverseKey[0][0] << " " << inverseKey[0][1] << "\n"
       << inverseKey[1][0] << " " << inverseKey[1][1];
    return ss.str();
}

std::vector<unsigned char> HillAlgorithm::hexToBytes(const std::string& hex) const {
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

std::string HillAlgorithm::bytesToHex(const std::vector<unsigned char>& data) const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string HillAlgorithm::generateKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    key = std::vector<std::vector<int>>(2, std::vector<int>(2));
    int det;
    
    do {
        key[0][0] = dis(gen);
        key[0][1] = dis(gen);
        key[1][0] = dis(gen);
        key[1][1] = dis(gen);
        
        det = key[0][0] * key[1][1] - key[0][1] * key[1][0];
    } while (std::gcd(det, 256) != 1);
    
    calculateInverseKey();
    
    return "Ключ Хилла (матрица 2x2):\n" +
           std::to_string(key[0][0]) + " " + std::to_string(key[0][1]) + "\n" +
           std::to_string(key[1][0]) + " " + std::to_string(key[1][1]);

}

void HillAlgorithm::calculateInverseKey() {
    int det = key[0][0] * key[1][1] - key[0][1] * key[1][0];
    int detInv = -1;
    
    for (int i = 1; i < 256; ++i) {
        if ((det * i) % 256 == 1) {
            detInv = i;
            break;
        }
    }
    
    if (detInv == -1) {
        throw std::runtime_error("Матрица не обратима по модулю 256");
    }
    
    inverseKey = std::vector<std::vector<int>>(2, std::vector<int>(2));
    inverseKey[0][0] = (key[1][1] * detInv) % 256;
    inverseKey[0][1] = (-key[0][1] * detInv) % 256;
    inverseKey[1][0] = (-key[1][0] * detInv) % 256;
    inverseKey[1][1] = (key[0][0] * detInv) % 256;
    
    for (auto& row : inverseKey) {
        for (auto& elem : row) {
            if (elem < 0) elem += 256;
        }
    }
}

std::vector<unsigned char> HillAlgorithm::processData(const std::vector<unsigned char>& data, 
                                                   const std::vector<std::vector<int>>& matrix) const {
    if (data.size() % 2 != 0) {
        throw std::runtime_error("Размер данных должен быть четным для шифрования Хилла 2x2");
    }
    
    std::vector<unsigned char> result;
    
    for (size_t i = 0; i < data.size(); i += 2) {
        int c1 = data[i];
        int c2 = (i + 1 < data.size()) ? data[i + 1] : 0;
        
        int e1 = (matrix[0][0] * c1 + matrix[0][1] * c2) % 256;
        int e2 = (matrix[1][0] * c1 + matrix[1][1] * c2) % 256;
        
        result.push_back(static_cast<unsigned char>(e1));
        result.push_back(static_cast<unsigned char>(e2));
    }
    
    return result;
}

std::string HillAlgorithm::getName() const {
    return "Hill Cipher";
}

std::string HillAlgorithm::encryptText(const std::string& text) {
    std::vector<unsigned char> data(text.begin(), text.end());
    
    if (data.size() % 2 != 0) {
        data.push_back(' ');
    }
    
    auto encrypted = processData(data, key);
    
    return bytesToHex(encrypted);
}

std::string HillAlgorithm::decryptText(const std::string& ciphertext) {
    std::string hex;
    for (char c : ciphertext) {
        if (isxdigit(c)) {
            hex += tolower(c);
        }
    }
    
    std::vector<unsigned char> data = hexToBytes(hex);
        
    if (data.size() % 2 != 0) {
        throw std::runtime_error("Размер данных должен быть четным для дешифрования Хилла 2x2");
    }
    
    auto decrypted = processData(data, inverseKey);
    
    std::string result;
    for (auto c : decrypted) {
        result += c;
    }
    return result;
}

void HillAlgorithm::encryptFile(const std::string& inputPath, const std::string& outputPath) {
    auto data = FileUtils::readBinaryFile(inputPath);
    
    if (data.size() % 2 != 0) {
        data.push_back(' ');
    }
    
    auto encrypted = processData(data, key);
    FileUtils::saveBinaryFile(outputPath, encrypted);
}

void HillAlgorithm::decryptFile(const std::string& inputPath, const std::string& outputPath) {
    auto data = FileUtils::readBinaryFile(inputPath);
    
    if (data.size() % 2 != 0) {
        throw std::runtime_error("Размер данных должен быть четным для дешифрования Хилла 2x2");
    }
    
    auto decrypted = processData(data, inverseKey);
    FileUtils::saveBinaryFile(outputPath, decrypted);
}


extern "C" {
    IEncryptionAlgorithm* createAlgorithm() {
        return new HillAlgorithm();
    }
    
    void destroyAlgorithm(IEncryptionAlgorithm* p) {
        delete p;
    }
}
