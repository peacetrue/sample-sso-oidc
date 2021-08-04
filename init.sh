#!/bin/bash

module_name=${1}

echo "初始化 $module_name 应用"

ssh $ali_ssh <<EOF
  mkdir "/root/peacetrue/$module_name"
EOF
