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

2. **Configure the application**
   Replace the placeholder key and certificate files in the keys/ folder with the correct ones for your organization in the Directory:
   ```
   keys/tpp_client_signing.key    ←  rtssigning.key
   keys/tpp_client_transport.crt  ←  brcac.pem
   keys/tpp_client_transport.key  ←  brcac.key
   ```

   Connecting to a different authorization server? Update the following files with your organization's data:

   `testdata/setup-localstack.sh` (line 118) — Update the client registration entry:
   ```json
   {"id": "<organisation_id>", "client_id": "<dcr_client_id>", "registration_token": "<dcr_registration_token>"}
   ```
   | Field                | Description                                              |
   |----------------------|----------------------------------------------------------|
   | `id`                 | Your organisation ID from the Directory                  |
   | `client_id`          | Client ID returned from Dynamic Client Registration (DCR)|
   | `registration_token` | Registration access token returned from DCR              |

   **`testdata/directory_id_token.json`** — Update the mock directory token with your organization details:
   | Field                                      | Description                                |
   |--------------------------------------------|--------------------------------------------|
   | `aud`                                      | Your software statement ID from Directory  |
   | `trust_framework_profile.org_access_details.<org_id>` | Your organisation ID as the key |
   | `trust_framework_profile.org_access_details.<org_id>.organisation_name` | Your organisation name |

3. **Run the services**

   ```bash
   make run
   ```
