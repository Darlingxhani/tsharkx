# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.28

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

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = F:\Cmake\bin\cmake.exe

# The command to remove a file.
RM = F:\Cmake\bin\cmake.exe -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = F:\code\vscodecpp\tshark

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = F:\code\vscodecpp\tshark\build

# Include any dependencies generated for this target.
include CMakeFiles/tshark.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/tshark.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/tshark.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/tshark.dir/flags.make

CMakeFiles/tshark.dir/main.cpp.obj: CMakeFiles/tshark.dir/flags.make
CMakeFiles/tshark.dir/main.cpp.obj: CMakeFiles/tshark.dir/includes_CXX.rsp
CMakeFiles/tshark.dir/main.cpp.obj: F:/code/vscodecpp/tshark/main.cpp
CMakeFiles/tshark.dir/main.cpp.obj: CMakeFiles/tshark.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=F:\code\vscodecpp\tshark\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/tshark.dir/main.cpp.obj"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/tshark.dir/main.cpp.obj -MF CMakeFiles\tshark.dir\main.cpp.obj.d -o CMakeFiles\tshark.dir\main.cpp.obj -c F:\code\vscodecpp\tshark\main.cpp

CMakeFiles/tshark.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/tshark.dir/main.cpp.i"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E F:\code\vscodecpp\tshark\main.cpp > CMakeFiles\tshark.dir\main.cpp.i

CMakeFiles/tshark.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/tshark.dir/main.cpp.s"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S F:\code\vscodecpp\tshark\main.cpp -o CMakeFiles\tshark.dir\main.cpp.s

CMakeFiles/tshark.dir/tsharkManager.cpp.obj: CMakeFiles/tshark.dir/flags.make
CMakeFiles/tshark.dir/tsharkManager.cpp.obj: CMakeFiles/tshark.dir/includes_CXX.rsp
CMakeFiles/tshark.dir/tsharkManager.cpp.obj: F:/code/vscodecpp/tshark/tsharkManager.cpp
CMakeFiles/tshark.dir/tsharkManager.cpp.obj: CMakeFiles/tshark.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=F:\code\vscodecpp\tshark\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/tshark.dir/tsharkManager.cpp.obj"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/tshark.dir/tsharkManager.cpp.obj -MF CMakeFiles\tshark.dir\tsharkManager.cpp.obj.d -o CMakeFiles\tshark.dir\tsharkManager.cpp.obj -c F:\code\vscodecpp\tshark\tsharkManager.cpp

CMakeFiles/tshark.dir/tsharkManager.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/tshark.dir/tsharkManager.cpp.i"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E F:\code\vscodecpp\tshark\tsharkManager.cpp > CMakeFiles\tshark.dir\tsharkManager.cpp.i

CMakeFiles/tshark.dir/tsharkManager.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/tshark.dir/tsharkManager.cpp.s"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S F:\code\vscodecpp\tshark\tsharkManager.cpp -o CMakeFiles\tshark.dir\tsharkManager.cpp.s

CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.obj: CMakeFiles/tshark.dir/flags.make
CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.obj: CMakeFiles/tshark.dir/includes_CXX.rsp
CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.obj: F:/code/vscodecpp/tshark/third_library/loguru/loguru.cpp
CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.obj: CMakeFiles/tshark.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=F:\code\vscodecpp\tshark\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.obj"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.obj -MF CMakeFiles\tshark.dir\third_library\loguru\loguru.cpp.obj.d -o CMakeFiles\tshark.dir\third_library\loguru\loguru.cpp.obj -c F:\code\vscodecpp\tshark\third_library\loguru\loguru.cpp

CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.i"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E F:\code\vscodecpp\tshark\third_library\loguru\loguru.cpp > CMakeFiles\tshark.dir\third_library\loguru\loguru.cpp.i

CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.s"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S F:\code\vscodecpp\tshark\third_library\loguru\loguru.cpp -o CMakeFiles\tshark.dir\third_library\loguru\loguru.cpp.s

CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.obj: CMakeFiles/tshark.dir/flags.make
CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.obj: CMakeFiles/tshark.dir/includes_CXX.rsp
CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.obj: F:/code/vscodecpp/tshark/third_library/ip2region/xdb_bench.cc
CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.obj: CMakeFiles/tshark.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=F:\code\vscodecpp\tshark\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.obj"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.obj -MF CMakeFiles\tshark.dir\third_library\ip2region\xdb_bench.cc.obj.d -o CMakeFiles\tshark.dir\third_library\ip2region\xdb_bench.cc.obj -c F:\code\vscodecpp\tshark\third_library\ip2region\xdb_bench.cc

CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.i"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E F:\code\vscodecpp\tshark\third_library\ip2region\xdb_bench.cc > CMakeFiles\tshark.dir\third_library\ip2region\xdb_bench.cc.i

CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.s"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S F:\code\vscodecpp\tshark\third_library\ip2region\xdb_bench.cc -o CMakeFiles\tshark.dir\third_library\ip2region\xdb_bench.cc.s

CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.obj: CMakeFiles/tshark.dir/flags.make
CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.obj: CMakeFiles/tshark.dir/includes_CXX.rsp
CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.obj: F:/code/vscodecpp/tshark/third_library/ip2region/xdb_search.cc
CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.obj: CMakeFiles/tshark.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=F:\code\vscodecpp\tshark\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.obj"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.obj -MF CMakeFiles\tshark.dir\third_library\ip2region\xdb_search.cc.obj.d -o CMakeFiles\tshark.dir\third_library\ip2region\xdb_search.cc.obj -c F:\code\vscodecpp\tshark\third_library\ip2region\xdb_search.cc

CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.i"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E F:\code\vscodecpp\tshark\third_library\ip2region\xdb_search.cc > CMakeFiles\tshark.dir\third_library\ip2region\xdb_search.cc.i

CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.s"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S F:\code\vscodecpp\tshark\third_library\ip2region\xdb_search.cc -o CMakeFiles\tshark.dir\third_library\ip2region\xdb_search.cc.s

CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.obj: CMakeFiles/tshark.dir/flags.make
CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.obj: CMakeFiles/tshark.dir/includes_CXX.rsp
CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.obj: F:/code/vscodecpp/tshark/third_library/ip2region/ip2region_util.cpp
CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.obj: CMakeFiles/tshark.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=F:\code\vscodecpp\tshark\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.obj"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.obj -MF CMakeFiles\tshark.dir\third_library\ip2region\ip2region_util.cpp.obj.d -o CMakeFiles\tshark.dir\third_library\ip2region\ip2region_util.cpp.obj -c F:\code\vscodecpp\tshark\third_library\ip2region\ip2region_util.cpp

CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.i"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E F:\code\vscodecpp\tshark\third_library\ip2region\ip2region_util.cpp > CMakeFiles\tshark.dir\third_library\ip2region\ip2region_util.cpp.i

CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.s"
	F:\program\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S F:\code\vscodecpp\tshark\third_library\ip2region\ip2region_util.cpp -o CMakeFiles\tshark.dir\third_library\ip2region\ip2region_util.cpp.s

# Object files for target tshark
tshark_OBJECTS = \
"CMakeFiles/tshark.dir/main.cpp.obj" \
"CMakeFiles/tshark.dir/tsharkManager.cpp.obj" \
"CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.obj" \
"CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.obj" \
"CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.obj" \
"CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.obj"

# External object files for target tshark
tshark_EXTERNAL_OBJECTS =

tshark.exe: CMakeFiles/tshark.dir/main.cpp.obj
tshark.exe: CMakeFiles/tshark.dir/tsharkManager.cpp.obj
tshark.exe: CMakeFiles/tshark.dir/third_library/loguru/loguru.cpp.obj
tshark.exe: CMakeFiles/tshark.dir/third_library/ip2region/xdb_bench.cc.obj
tshark.exe: CMakeFiles/tshark.dir/third_library/ip2region/xdb_search.cc.obj
tshark.exe: CMakeFiles/tshark.dir/third_library/ip2region/ip2region_util.cpp.obj
tshark.exe: CMakeFiles/tshark.dir/build.make
tshark.exe: CMakeFiles/tshark.dir/linkLibs.rsp
tshark.exe: CMakeFiles/tshark.dir/objects1.rsp
tshark.exe: CMakeFiles/tshark.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=F:\code\vscodecpp\tshark\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking CXX executable tshark.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\tshark.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/tshark.dir/build: tshark.exe
.PHONY : CMakeFiles/tshark.dir/build

CMakeFiles/tshark.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\tshark.dir\cmake_clean.cmake
.PHONY : CMakeFiles/tshark.dir/clean

CMakeFiles/tshark.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" F:\code\vscodecpp\tshark F:\code\vscodecpp\tshark F:\code\vscodecpp\tshark\build F:\code\vscodecpp\tshark\build F:\code\vscodecpp\tshark\build\CMakeFiles\tshark.dir\DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/tshark.dir/depend

