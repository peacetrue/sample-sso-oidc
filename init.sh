#!/bin/bash

module_name=${1}
port=${2}
env=${3-prod}

echo "初始化 $module_name 应用"

ssh $ali_ssh <<EOF
  mkdir "/root/peacetrue/$module_name"
EOF
