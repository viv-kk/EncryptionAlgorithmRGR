#ifndef ENCRYPTION_INTERFACE_H
#define ENCRYPTION_INTERFACE_H

#include <string>
#include <vector>
#include <memory>

class IEncryptionAlgorithm {
public:
    virtual ~IEncryptionAlgorithm() = default;
   
    virtual std::string getName() const = 0;
    virtual std::string encryptText(const std::string& text) = 0;
    virtual std::string decryptText(const std::string& ciphertext) = 0;
    virtual void encryptFile(const std::string& inputPath, const std::string& outputPath) = 0;
    virtual void decryptFile(const std::string& inputPath, const std::string& outputPath) = 0;
    virtual bool requiresKey() const = 0;

    virtual std::string getKey() const = 0;
};

using CreateAlgorithmFunc = IEncryptionAlgorithm* (*)();
using DestroyAlgorithmFunc = void (*)(IEncryptionAlgorithm*);

#endif // ENCRYPTION_INTERFACE_H
