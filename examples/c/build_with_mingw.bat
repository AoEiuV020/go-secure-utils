@echo off
echo 使用MinGW编译C示例...

REM 清理旧的构建目录
if exist build rmdir /s /q build
mkdir build
cd build

REM 使用MinGW Makefiles生成器配置CMake项目
cmake -G "MinGW Makefiles" ..

REM 构建项目
cmake --build .

echo 构建完成，正在运行示例...
rsa_example.exe

cd ..
