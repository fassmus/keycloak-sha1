# Keycloak SHA1

Add a password hash provider to handle SHA1 passwords inside Keycloak (e.g. migration from OpenLDAP).

## Build
```bash
./gradlew jar
```

## Test with docker-compose
```bash
cp build/libs/keycloak-sha1-1.0.0.jar docker/
docker-compose up -d
```

## Install
```
curl -L https://github.com/fassmus/keycloak-sha1/releases/download/1.0.0/keycloak-sha1-1.0.0.jar > KEYCLOAK_HOME/standalone/deployments/keycloak-sha1-1.0.0.jar
```
You need to restart Keycloak.

## How to use
Go to `Authentication` / `Password policy` and add hashing algorithm policy with value `sha1`.

To test if installation works, create new user and set its credentials.
