#include "/home/vikct/EncryptionAlgorithmRGR/include/algorithms/rsa.h"
#include "/home/vikct/EncryptionAlgorithmRGR/include/core/file_utils.h"
#include <iostream>
#include <random>
#include <fstream>
#include <sstream>
#include <vector>
#include <cmath>
#include <numeric>
#include <stdexcept>
 
RSAAlgorithm::RSAAlgorithm() {
    generatePrimes();
    generateKeys();
}
std::string RSAAlgorithm::getKey() const {
    std::stringstream ss;
    ss << "Открытый ключ: (" << e << ", " << n << ")\n"
       << "Закрытый ключ: (" << d << ", " << n << ")\n"
       << "p = " << p << ", q = " << q << "\n";
    return ss.str();
}

bool RSAAlgorithm::isPrime(int num) const {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;
    
    for (int i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0)
            return false;
    }
    return true;
}

void RSAAlgorithm::generatePrimes() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 10000);
    
    do {
        p = dis(gen);
    } while (!isPrime(p));
    
    do {
        q = dis(gen);
    } while (!isPrime(q) || q == p);
}

void RSAAlgorithm::generateKeys() {
    n = p * q;
    int phi = (p - 1) * (q - 1);

    if (p == 0 || q == 0) {
        throw std::runtime_error("Простые числа p и q не инициализированы");
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(2, phi - 1);
    
    for (e = 2; e < phi; e++) {
        if (std::gcd(e, phi) == 1) break;
    }

    for (d = 1; d < phi; d++) {
        if ((e * d) % phi == 1) break;
    }
}

uint64_t RSAAlgorithm::modPow(uint64_t base, int exp, int mod) const {
    uint64_t result = 1;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        base = (base * base) % mod;
        exp = exp >> 1;
    }
    return result;
}

std::string RSAAlgorithm::getName() const {
    return "RSA Encryption";
}

std::string RSAAlgorithm::encryptText(const std::string& text) {
    std::vector<unsigned char> data(text.begin(), text.end());
    std::vector<uint64_t> encrypted;
    
    for (unsigned char c : data) {
        uint64_t m = static_cast<int>(c);
        if (m >= n) {
            throw std::runtime_error("Символ '" + std::string(1, c) + "' (код " + std::to_string(m) +
                ") слишком большой для выбранных ключей");
        }
        encrypted.push_back(modPow(m, e, n));
    }
    
    std::string result;
    for (auto num : encrypted) {
        result += std::to_string(num) + " ";
    }
    return result;
}

std::string RSAAlgorithm::decryptText(const std::string& ciphertext) {
    std::vector<uint64_t> encryptedNumbers;
    std::istringstream iss(ciphertext);
    std::string token;
    
    while (iss >> token) {
        try {
            uint64_t num = std::stoull(token);
            encryptedNumbers.push_back(num);
        } catch (...) {
            throw std::runtime_error("Неверный формат зашифрованных данных. Ожидаются числа, разделенные пробелами.");
        }
    }
    
    std::string decrypted;
    for (uint64_t cipher : encryptedNumbers) {
        uint64_t m = modPow(cipher, d, n);
        decrypted += static_cast<char>(m);
    }
    
    return decrypted;
}

void RSAAlgorithm::encryptFile(const std::string& inputPath, const std::string& outputPath) {
    auto data = FileUtils::readBinaryFile(inputPath);
    std::vector<uint64_t> encrypted;
    
    for (unsigned char c : data) {
        uint64_t m = static_cast<int>(c);
        if (m >= n) {
            throw std::runtime_error("Символ с кодом " + std::to_string(m) + 
                " слишком большой для выбранных ключей");
        }
        encrypted.push_back(modPow(m, e, n));
    }
    
    FileUtils::saveEncryptedToFile(outputPath, encrypted);
}

void RSAAlgorithm::decryptFile(const std::string& inputPath, const std::string& outputPath) {
    auto encrypted = FileUtils::readEncryptedFile(inputPath);
    std::vector<unsigned char> decrypted;
    
    for (uint64_t cipher : encrypted) {
        uint64_t m = modPow(cipher, d, n);
        decrypted.push_back(static_cast<unsigned char>(m));
    }
    
    FileUtils::saveBinaryFile(outputPath, decrypted);
}


extern "C" {
    IEncryptionAlgorithm* createAlgorithm() {
        return new RSAAlgorithm();
    }
    
    void destroyAlgorithm(IEncryptionAlgorithm* p) {
        delete p;
    }
}
