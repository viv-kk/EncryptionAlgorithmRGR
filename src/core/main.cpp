#include "/home/vikct/EncryptionAlgorithmRGR/include/core/menu_controller.h"
#include <locale>
#include <iostream>
int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
   
    try {
        MenuController controller;
        controller.run();
    } catch (const std::exception& e) {
        std::cerr << "Критическая ошибка: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
