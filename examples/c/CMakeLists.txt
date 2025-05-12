cmake_minimum_required(VERSION 3.10)
project(rsa_example C)

# 设置C标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 定义库名(不带前缀和扩展名)
set(LIBRARY_NAME go_secure_utils)

# 指定构建目录的相对路径
set(PREBUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../build/prebuild")

# 处理不同操作系统和架构的映射
if(WIN32)
    set(SYSTEM_NAME "Windows")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SYSTEM_PROCESSOR "AMD64")
    else()
        set(SYSTEM_PROCESSOR "x86")
    endif()
elseif(ANDROID)
    set(SYSTEM_NAME "Android")
    # Android NDK会设置CMAKE_ANDROID_ARCH_ABI
    set(SYSTEM_PROCESSOR ${CMAKE_ANDROID_ARCH_ABI})
elseif(APPLE)
    if(IOS)
        set(SYSTEM_NAME "iOS") 
    else()
        set(SYSTEM_NAME "macOS")
    endif()
    
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
        set(SYSTEM_PROCESSOR "arm64")
    else()
        set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
    endif()
else()
    # Linux或其他Unix系统
    set(SYSTEM_NAME "Linux")
    set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
endif()

# 构建库的完整路径
set(LIBRARY_PATH "${PREBUILD_DIR}/${SYSTEM_NAME}/${SYSTEM_PROCESSOR}")

# 设置动态库和导入库文件的完整路径
if(WIN32)
    set(FULL_LIBRARY_PATH "${LIBRARY_PATH}/${LIBRARY_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(FULL_IMPLIB_PATH "${LIBRARY_PATH}/${LIBRARY_NAME}.lib")
else()
    set(FULL_LIBRARY_PATH "${LIBRARY_PATH}/lib${LIBRARY_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}")
endif()

# 如果库不存在，给出友好的错误信息
if(NOT EXISTS "${FULL_LIBRARY_PATH}")
    message(FATAL_ERROR "找不到所需的动态库: ${FULL_LIBRARY_PATH}\n请先在主项目目录运行 'make' 构建共享库")
endif()

# 添加头文件搜索路径
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../..)

# 设置字符集为Unicode (解决中文编码问题)
if(MSVC)
    add_compile_options(/utf-8)
endif()

# 生成可执行文件
add_executable(rsa_example rsa_example.c)

# 复制动态库到输出目录
add_custom_command(TARGET rsa_example POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${FULL_LIBRARY_PATH}
        $<TARGET_FILE_DIR:rsa_example>
    COMMENT "复制动态库到输出目录"
)

# 链接动态库
if(WIN32)
    # 检测编译器类型
    if(MSVC)
        # MSVC编译器需要导入库
        if(EXISTS "${FULL_IMPLIB_PATH}")
            target_link_libraries(rsa_example "${FULL_IMPLIB_PATH}")
        else()
            message(FATAL_ERROR "找不到所需的导入库: ${FULL_IMPLIB_PATH}\n请先运行 'create_lib.bat' 生成导入库")
        endif()
    else()
        # MinGW/GCC可以直接指定DLL的完整路径
        target_link_libraries(rsa_example "${FULL_LIBRARY_PATH}")
    endif()
else()
    link_directories(${LIBRARY_PATH})
    target_link_libraries(rsa_example ${LIBRARY_NAME})
endif()

# 添加一个自定义目标用于清理
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_CURRENT_BINARY_DIR}/rsa_example${CMAKE_EXECUTABLE_SUFFIX}
    COMMENT "清理所有构建文件"
)
