#!/bin/bash
set -e

TOKEN_LABEL="${SOFTHSM_TOKEN_LABEL:-PkiCA}"
SO_PIN="${SOFTHSM_SO_PIN:-12345678}"
USER_PIN="${SOFTHSM_USER_PIN:-1234}"

# Initialize token on first run (skip if tokens already exist)
if [ ! "$(ls -A /var/lib/softhsm/tokens/ 2>/dev/null)" ]; then
    echo "==> Initializing SoftHSM2 token: ${TOKEN_LABEL}"
    softhsm2-util --init-token --free --label "${TOKEN_LABEL}" \
        --so-pin "${SO_PIN}" --pin "${USER_PIN}"
    echo "==> Token initialized. Slot info:"
    softhsm2-util --show-slots
else
    echo "==> SoftHSM2 tokens already exist:"
    softhsm2-util --show-slots
fi

# Copy library to shared volume (in case volume was recreated)
cp -f /usr/lib/softhsm/libsofthsm2.so /shared/lib/libsofthsm2.so

echo "==> SoftHSM2 ready. Container staying alive for admin commands."
echo "    Use: podman exec softhsm2 softhsm2-util --show-slots"
echo "    Use: podman exec softhsm2 pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -L"

# Stay alive — this container is a service, not a one-shot init
exec tail -f /dev/null
