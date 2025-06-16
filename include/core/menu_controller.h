#ifndef MENU_CONTROLLER_H
#define MENU_CONTROLLER_H

#include "encryption_interface.h"
#include <vector>
#include <memory>
#include <string>

class MenuController {
private:
    std::vector<std::pair<std::string, void*>> loadedLibraries;
    std::unique_ptr<IEncryptionAlgorithm> currentAlgorithm;
   
    void loadAlgorithms();
    void unloadAlgorithms();
    void showMainMenu();
    void showAlgorithmMenu();
    void processTextEncryption();
    void processTextDecryption();
    void processFileEncryption();
    void processFileDecryption();
    
public:
    MenuController();
    ~MenuController();
    void run();
};

#endif // MENU_CONTROLLER_H
