# soracom-beam-signature-verifier-example-go

## Support services

- SORACOM Air for Cellular
  - HTTP
  - TCP
  - UDP
  - SMS
  - USSD
- SORACOM Air for Sigfox
- SORACOM Air for LoRaWAN (JP Only)
- SORACOM Inventory (LwM2M Notify adapter)

## How to run

Set the server port and Pre-Shared Key with the environment variables, and start server.

```bash
make build
SERVER_PORT=8090 SORACOM_BEAM_SHARED_SECRET=topsecret bin/soracom-beam-signature-verifier-example-go*
```

Request the following on the device with SORACOM Beam configured to the SORACOM Beam endopoint.

```bash
curl http://beam.soracom.io
```

## What is SORACOM Beam signature header?

See also following link:
https://developers.soracom.io/en/docs/beam/signature-verification/
