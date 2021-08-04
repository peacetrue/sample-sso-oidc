#!/bin/bash

module_name=${1}
port=${2}
env=${3-prod}

echo "重启$module_name($port $env)应用"

ssh $ali_ssh <<EOF
killbp "$port"
echo "cd /root/peacetrue/$module_name"
cd "/root/peacetrue/$module_name"
echo "nohup java -Xmx256m -Xms256m -Xmn96m -Xss256k -Dspring.profiles.active=$env -jar $module_name-1.0.0-SNAPSHOT.jar >/dev/null 2>&1  &"
nohup java -Xmx256m -Xms256m -Xmn96m -Xss256k "-Dspring.profiles.active=$env" -jar "$module_name-1.0.0-SNAPSHOT.jar" >/dev/null 2>&1  &
EOF
