# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

project(go_secure_utils_library VERSION 0.0.1 LANGUAGES C)

add_library(go_secure_utils SHARED
  "go_secure_utils.c"
)

set_target_properties(go_secure_utils PROPERTIES
  PUBLIC_HEADER go_secure_utils.h
  OUTPUT_NAME "go_secure_utils"
)

target_compile_definitions(go_secure_utils PUBLIC DART_SHARED_LIB)

if (ANDROID)
  # Support Android 15 16k page size
  target_link_options(go_secure_utils PRIVATE "-Wl,-z,max-page-size=16384")
endif()
