#!/bin/bash

sh ../deploy.sh sample-sso-oidc-idp 9300 "prod"
sh ../restart.sh sample-sso-oidc-idp 9300 "prod"

