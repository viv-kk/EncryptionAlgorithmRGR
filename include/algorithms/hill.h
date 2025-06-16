#ifndef HILL_ALGORITHM_H
#define HILL_ALGORITHM_H

#include "/home/vikct/EncryptionAlgorithmRGR/include/core/encryption_interface.h"
#include <vector>
#include <string>

class HillAlgorithm : public IEncryptionAlgorithm {
private:
    std::vector<std::vector<int>> key;
    std::vector<std::vector<int>> inverseKey;

    void calculateInverseKey();
    std::vector<unsigned char> processData(const std::vector<unsigned char>& data, 
                                         const std::vector<std::vector<int>>& matrix) const;
    std::string bytesToHex(const std::vector<unsigned char>& data) const;    
    std::vector<unsigned char> hexToBytes(const std::string& hex) const;
    std::string generateKey();

public:
    HillAlgorithm();
    std::string getKey() const override;
    std::string getName() const override;
    std::string encryptText(const std::string& text) override;
    std::string decryptText(const std::string& ciphertext) override;
    void encryptFile(const std::string& inputPath, const std::string& outputPath) override;
    void decryptFile(const std::string& inputPath, const std::string& outputPath) override;
    bool requiresKey() const override { return false; }
};

#endif // HILL_ALGORITHM_H
