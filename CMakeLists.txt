cmake_minimum_required(VERSION 3.10)
project(EncryptionAlgorithmRGR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Настройка выходных директорий
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

# Включение директорий
include_directories(include)

# Основное приложение
add_executable(EncryptionAlgorithmRGR
    src/core/main.cpp
    src/core/menu_controller.cpp
    src/core/file_utils.cpp
)

# Динамические библиотеки алгоритмов
add_library(rsa SHARED src/algorithms/rsa.cpp src/core/file_utils.cpp)
target_include_directories(rsa PUBLIC include)

add_library(hill SHARED src/algorithms/hill.cpp src/core/file_utils.cpp)
target_include_directories(hill PUBLIC include)

add_library(vernam SHARED src/algorithms/vernam.cpp src/core/file_utils.cpp)
target_include_directories(vernam PUBLIC include)

# Связывание с библиотекой dl для динамической загрузки
target_link_libraries(EncryptionAlgorithmRGR dl)
