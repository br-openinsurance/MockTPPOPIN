# MockTPPOPIN

A mock third party provider (TPP) implementation for the Open Insurance Brazil ecosystem.

## Prerequisites

- Docker and Docker Compose
- Go 1.24 or later
- Make (for build commands)

The following hosts must be configured in the system:

```
mocktpp.local
directory.local
matls-directory.local
aws.local
```

## Quick Start

1. **Set up the local environment**
   ```bash
   make setup
   ```

2. **Configure the application keys**
   Replace the placeholder key and certificate files in the keys/ directory with the correct ones:
   ```
   keys/tpp_client_signing.key    ←  rtssigning.key
   keys/tpp_client_transport.crt  ←  brcac.pem
   keys/tpp_client_transport.key  ←  brcac.key
   ```
   You can request these files from the team leads or retrieve them from the `tf-mock-tpp-deployment` repository.

3. **Run the services**

   ```bash
   make run
   ```

## Running dev and sandbox

To run Mock TPP using the dev or sandbox environments (without the local mock), change the values for `DirectoryIssuer` and `DirectoryAPIHost` in `cmd/server/main.go` to the commented ones.