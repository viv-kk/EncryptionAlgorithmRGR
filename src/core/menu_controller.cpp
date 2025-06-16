#include "/home/vikct/EncryptionAlgorithmRGR/include/core/menu_controller.h"
#include "/home/vikct/EncryptionAlgorithmRGR/include/core/file_utils.h"
#include <iostream>
#include <dlfcn.h>
#include <memory>
#include <limits>
MenuController::MenuController() {
    loadAlgorithms();
}
 
MenuController::~MenuController() {
    unloadAlgorithms();
}

void MenuController::loadAlgorithms() {
    const std::vector<std::string> libs = {
        "/home/vikct/EncryptionAlgorithmRGR/lib/librsa.so",
        "/home/vikct/EncryptionAlgorithmRGR/lib/libhill.so",
        "/home/vikct/EncryptionAlgorithmRGR/lib/libvernam.so"
    };

    for (const auto& lib : libs) {
        void* handle = dlopen(lib.c_str(), RTLD_LAZY);
        if (handle) {
            loadedLibraries.emplace_back(lib, handle);
        } else {
            std::cerr << "Не удалось загрузить библиотеку " << lib << ": " << dlerror() << std::endl;
        }
    }
}

void MenuController::unloadAlgorithms() {
    for (auto& [name, handle] : loadedLibraries) {
        if (handle) {
            dlclose(handle);
        }
    }
}

void MenuController::run() {
    while (true) {
        showMainMenu();
    }
}

void MenuController::showMainMenu() {
    while (true) {
        std::cout << "\n=== Encryption Algorithm RGR ===\n";
        std::cout << "1. Выбрать алгоритм шифрования\n";
        std::cout << "2. Шифрование текста\n";
        std::cout << "3. Дешифрование текста\n";
        std::cout << "4. Шифрование файла\n";
        std::cout << "5. Дешифрование файла\n";
        std::cout << "6. Выход\n";
        std::cout << "Выберите действие: ";

        int choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Неверный выбор. Попробуйте снова.\n";
            continue;
        }

        try {
            switch (choice) {
                case 1:
                    showAlgorithmMenu();
                    break;
                case 2:
                    processTextEncryption();
                    break;
                case 3:
                    processTextDecryption();
                    break;
                case 4:
                    processFileEncryption();
                    break;
                case 5:
                    processFileDecryption();
                    break;
                case 6:
                    std::cout << "Выход из программы.\n";
                    exit(0);
                default:
                    std::cout << "Неверный выбор. Попробуйте снова.\n";
		    
            }
        } catch (const std::exception& e) {
            std::cerr << "Ошибка: " << e.what() << std::endl;
        }
    }
}

void MenuController::showAlgorithmMenu() {
    if (loadedLibraries.empty()) {
        std::cout << "Нет доступных алгоритмов шифрования.\n";
        return;
    }
    
    std::cout << "\nДоступные алгоритмы:\n";
    for (size_t i = 0; i < loadedLibraries.size(); ++i) {
        void* handle = loadedLibraries[i].second;
        auto createFunc = (CreateAlgorithmFunc)dlsym(handle, "createAlgorithm");
        if (createFunc) {
            std::unique_ptr<IEncryptionAlgorithm> temp(createFunc());
            std::cout << i + 1 << ". " << temp->getName() << "\n";
        }
    }
    
    while (true) {
        std::cout << "Выберите алгоритм: ";
        int algChoice;
        std::cin >> algChoice;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Ошибка: введите число от 1 до " << loadedLibraries.size() << ".\n";
            continue;
        }
        
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        
        if (algChoice > 0 && algChoice <= static_cast<int>(loadedLibraries.size())) {
            void* handle = loadedLibraries[algChoice - 1].second;
            auto createFunc = (CreateAlgorithmFunc)dlsym(handle, "createAlgorithm");
            if (createFunc) {
                currentAlgorithm.reset(createFunc());
                std::cout << "Выбран алгоритм: " << currentAlgorithm->getName() << "\n";
                break;
            }
        } else {
            std::cout << "Неверный выбор.\n";
        }
    }
}

void MenuController::processTextEncryption() {
    if (!currentAlgorithm) {
        std::cout << "Сначала выберите алгоритм шифрования.\n";
        return;
    }
    
    std::cout << "Введите текст для шифрования: ";
    std::string text;
    std::getline(std::cin, text);
    
    try {
        std::string encrypted = currentAlgorithm->encryptText(text);
        std::cout << "Результат шифрования:\n" << encrypted << "\n";
        std::cout << "\nИспользованные ключи:\n" << currentAlgorithm->getKey() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Ошибка при шифровании: " << e.what() << std::endl;
    }
}

void MenuController::processTextDecryption() {
    if (!currentAlgorithm) {
        std::cout << "Сначала выберите алгоритм шифрования.\n";
        return;
    }
    
    std::cout << "Введите текст для дешифрования: ";
    std::string text;
    std::getline(std::cin, text);
    
    try {
        std::string decrypted = currentAlgorithm->decryptText(text);
        std::cout << "Результат дешифрования:\n" << decrypted << "\n";
        std::cout << "\nИспользованные ключи:\n" << currentAlgorithm->getKey() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Ошибка при дешифровании: " << e.what() << std::endl;
    }
}

void MenuController::processFileEncryption() {
    if (!currentAlgorithm) {
        std::cout << "Сначала выберите алгоритм шифрования.\n";
        return;
    }
    
    std::cout << "Введите путь к файлу для шифрования: ";
    std::string inputPath;
    std::getline(std::cin, inputPath);
    
    if (!FileUtils::fileExists(inputPath)) {
        std::cout << "Файл не существует. Хотите создать его? (y/n): ";
        char choice;
        std::cin >> choice;
        std::cin.ignore();
        
        if (choice == 'y' || choice == 'Y') {
            try {
                FileUtils::createFile(inputPath);
                std::cout << "Файл успешно создан.\n";
            } catch (const std::exception& e) {
                std::cerr << "Ошибка при создании файла: " << e.what() << std::endl;
                return;
            }
        } else {
            std::cout << "Операция отменена.\n";
            return;
        }
    }

    std::cout << "Введите путь для сохранения зашифрованного файла: ";
    std::string outputPath;
    std::getline(std::cin, outputPath);

    try {
        currentAlgorithm->encryptFile(inputPath, outputPath);
        std::cout << "Файл успешно зашифрован и сохранен как " << outputPath << "\n";
        std::cout << "\nИспользованные ключи:\n" << currentAlgorithm->getKey() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Ошибка при шифровании файла: " << e.what() << std::endl;
    }
}

void MenuController::processFileDecryption() {
    if (!currentAlgorithm) {
        std::cout << "Сначала выберите алгоритм шифрования.\n";
        return;
    }
    
    std::cout << "Введите путь к зашифрованному файлу: ";
    std::string inputPath;
    std::getline(std::cin, inputPath);

    if (!FileUtils::fileExists(inputPath)) {
        std::cout << "Файл не существует. Хотите создать его? (y/n): ";
        char choice;
        std::cin >> choice;
        std::cin.ignore();
        
        if (choice == 'y' || choice == 'Y') {
            try {
                FileUtils::createFile(inputPath);
                std::cout << "Файл успешно создан.\n";
            } catch (const std::exception& e) {
                std::cerr << "Ошибка при создании файла: " << e.what() << std::endl;
                return;
            }
        } else {
            std::cout << "Операция отменена.\n";
            return;
        }
    }
    
    std::cout << "Введите путь для сохранения расшифрованного файла: ";
    std::string outputPath;
    std::getline(std::cin, outputPath);
    
    try {
        currentAlgorithm->decryptFile(inputPath, outputPath);
        std::cout << "Файл успешно расшифрован и сохранен как " << outputPath << "\n";
        std::cout << "\nИспользованные ключи:\n" << currentAlgorithm->getKey() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Ошибка при дешифровании файла: " << e.what() << std::endl;
    }
}
