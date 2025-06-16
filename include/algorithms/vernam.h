#ifndef VERNAM_ALGORITHM_H
#define VERNAM_ALGORITHM_H

#include "/home/vikct/EncryptionAlgorithmRGR/include/core/encryption_interface.h"
#include <string>

class VernamAlgorithm : public IEncryptionAlgorithm {
private:
    std::string generateKeyFromPassword(const std::string& password, size_t requiredLength) const;

public:
    std::string getKey() const override;
    std::string getName() const override;
    std::string encryptText(const std::string& text) override;
    std::string decryptText(const std::string& ciphertext) override;
    void encryptFile(const std::string& inputPath, const std::string& outputPath) override;
    void decryptFile(const std::string& inputPath, const std::string& outputPath) override;
    bool requiresKey() const override { return true; }
    std::string bytesToHex(const std::vector<unsigned char>& data) const;
    std::vector<unsigned char> hexToBytes(const std::string& hex) const;
};

#endif // VERNAM_ALGORITHM_H
