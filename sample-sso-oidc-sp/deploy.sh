#!/bin/bash

sh ../deploy.sh sample-sso-oidc-sp
sh ../restart.sh sample-sso-oidc-sp 9301 "prod,client1"
sh ../restart.sh sample-sso-oidc-sp 9302 "prod,client2"

# nohup java -Xmx256m -Xms256m -Xmn96m -Xss256k "-Dspring.profiles.active=prod,test" -jar "idaas-jwt-web-1.0.0-SNAPSHOT.jar" >/dev/null 2>&1  &
# nohup java -Xmx256m -Xms256m -Xmn96m -Xss256k "-Dspring.profiles.active=prod,test,dup" -jar "idaas-jwt-web-1.0.0-SNAPSHOT.jar" >/dev/null 2>&1  &
