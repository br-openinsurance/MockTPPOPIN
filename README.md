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
   Replace the placeholder key and certificate files in the keys/ folder with the correct ones for your organization in the Directory:
   ```
   keys/tpp_client_signing.key    ←  rtssigning.key
   keys/tpp_client_transport.crt  ←  brcac.pem
   keys/tpp_client_transport.key  ←  brcac.key
   ```

3. **Run the services**

   ```bash
   make run
   ```
