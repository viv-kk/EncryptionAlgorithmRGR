#ifndef RSA_ALGORITHM_H
#define RSA_ALGORITHM_H

#include "/home/vikct/EncryptionAlgorithmRGR/include/core/encryption_interface.h"
#include <vector>
#include <string>

class RSAAlgorithm : public IEncryptionAlgorithm {
private:
    int p;
    int q;
    int n, e, d;

    bool isPrime(int num) const;
    void generatePrimes();
    void generateKeys();
    uint64_t modPow(uint64_t base, int exp, int mod) const;
   
public:
    RSAAlgorithm();
    std::string getKey() const override;    
    std::string getName() const override;
    std::string encryptText(const std::string& text) override;
    std::string decryptText(const std::string& ciphertext) override;
    void encryptFile(const std::string& inputPath, const std::string& outputPath) override;
    void decryptFile(const std::string& inputPath, const std::string& outputPath) override;
    bool requiresKey() const override { return false; }
};

#endif // RSA_ALGORITHM_H
