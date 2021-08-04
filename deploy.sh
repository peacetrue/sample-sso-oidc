#!/bin/bash

# 部署脚本：从本地部署应用到个人阿里云服务器

module_name=${1}
port=${2}
env=${3-prod}

echo "部署$module_name($port $env)应用"

echo "当前所在目录：$(pwd)"

../gradlew "clean"
../gradlew "bootJar"

scp "build/libs/$module_name-1.0.0-SNAPSHOT.jar" "$ali_ssh:/root/peacetrue/$module_name"

