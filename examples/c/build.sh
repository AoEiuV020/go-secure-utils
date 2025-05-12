#!/bin/bash
set -e
echo "使用CMake编译C示例..."

# 清理旧的构建目录
if [ -d "build" ]; then
    rm -rf build
fi
mkdir build
cd build

# 配置CMake项目
cmake ..

# 构建项目
cmake --build .

echo "构建完成，正在运行示例..."
./rsa_example

cd ..
