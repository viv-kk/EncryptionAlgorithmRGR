# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/vikct/EncryptionAlgorithmRGR

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/vikct/EncryptionAlgorithmRGR/build

# Include any dependencies generated for this target.
include CMakeFiles/EncryptionAlgorithmRGR.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/EncryptionAlgorithmRGR.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/EncryptionAlgorithmRGR.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/EncryptionAlgorithmRGR.dir/flags.make

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o: CMakeFiles/EncryptionAlgorithmRGR.dir/flags.make
CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o: /home/vikct/EncryptionAlgorithmRGR/src/core/main.cpp
CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o: CMakeFiles/EncryptionAlgorithmRGR.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/vikct/EncryptionAlgorithmRGR/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o -MF CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o.d -o CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o -c /home/vikct/EncryptionAlgorithmRGR/src/core/main.cpp

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vikct/EncryptionAlgorithmRGR/src/core/main.cpp > CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.i

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vikct/EncryptionAlgorithmRGR/src/core/main.cpp -o CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.s

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o: CMakeFiles/EncryptionAlgorithmRGR.dir/flags.make
CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o: /home/vikct/EncryptionAlgorithmRGR/src/core/menu_controller.cpp
CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o: CMakeFiles/EncryptionAlgorithmRGR.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/vikct/EncryptionAlgorithmRGR/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o -MF CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o.d -o CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o -c /home/vikct/EncryptionAlgorithmRGR/src/core/menu_controller.cpp

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vikct/EncryptionAlgorithmRGR/src/core/menu_controller.cpp > CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.i

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vikct/EncryptionAlgorithmRGR/src/core/menu_controller.cpp -o CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.s

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o: CMakeFiles/EncryptionAlgorithmRGR.dir/flags.make
CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o: /home/vikct/EncryptionAlgorithmRGR/src/core/file_utils.cpp
CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o: CMakeFiles/EncryptionAlgorithmRGR.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/vikct/EncryptionAlgorithmRGR/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o -MF CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o.d -o CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o -c /home/vikct/EncryptionAlgorithmRGR/src/core/file_utils.cpp

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/vikct/EncryptionAlgorithmRGR/src/core/file_utils.cpp > CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.i

CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/vikct/EncryptionAlgorithmRGR/src/core/file_utils.cpp -o CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.s

# Object files for target EncryptionAlgorithmRGR
EncryptionAlgorithmRGR_OBJECTS = \
"CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o" \
"CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o" \
"CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o"

# External object files for target EncryptionAlgorithmRGR
EncryptionAlgorithmRGR_EXTERNAL_OBJECTS =

/home/vikct/EncryptionAlgorithmRGR/bin/EncryptionAlgorithmRGR: CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/main.cpp.o
/home/vikct/EncryptionAlgorithmRGR/bin/EncryptionAlgorithmRGR: CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/menu_controller.cpp.o
/home/vikct/EncryptionAlgorithmRGR/bin/EncryptionAlgorithmRGR: CMakeFiles/EncryptionAlgorithmRGR.dir/src/core/file_utils.cpp.o
/home/vikct/EncryptionAlgorithmRGR/bin/EncryptionAlgorithmRGR: CMakeFiles/EncryptionAlgorithmRGR.dir/build.make
/home/vikct/EncryptionAlgorithmRGR/bin/EncryptionAlgorithmRGR: CMakeFiles/EncryptionAlgorithmRGR.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/vikct/EncryptionAlgorithmRGR/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable /home/vikct/EncryptionAlgorithmRGR/bin/EncryptionAlgorithmRGR"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/EncryptionAlgorithmRGR.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/EncryptionAlgorithmRGR.dir/build: /home/vikct/EncryptionAlgorithmRGR/bin/EncryptionAlgorithmRGR
.PHONY : CMakeFiles/EncryptionAlgorithmRGR.dir/build

CMakeFiles/EncryptionAlgorithmRGR.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/EncryptionAlgorithmRGR.dir/cmake_clean.cmake
.PHONY : CMakeFiles/EncryptionAlgorithmRGR.dir/clean

CMakeFiles/EncryptionAlgorithmRGR.dir/depend:
	cd /home/vikct/EncryptionAlgorithmRGR/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/vikct/EncryptionAlgorithmRGR /home/vikct/EncryptionAlgorithmRGR /home/vikct/EncryptionAlgorithmRGR/build /home/vikct/EncryptionAlgorithmRGR/build /home/vikct/EncryptionAlgorithmRGR/build/CMakeFiles/EncryptionAlgorithmRGR.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/EncryptionAlgorithmRGR.dir/depend

