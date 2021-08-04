#!/bin/bash

sh ../deploy.sh sample-sso-oidc-idp 9300 "prod"
sh ../restart.sh sample-sso-oidc-sp 9300 "prod"

# nohup java -Xmx256m -Xms256m -Xmn96m -Xss256k "-Dspring.profiles.active=prod,test" -jar "idaas-jwt-web-1.0.0-SNAPSHOT.jar" >/dev/null 2>&1  &
# nohup java -Xmx256m -Xms256m -Xmn96m -Xss256k "-Dspring.profiles.active=prod,test,dup" -jar "idaas-jwt-web-1.0.0-SNAPSHOT.jar" >/dev/null 2>&1  &
