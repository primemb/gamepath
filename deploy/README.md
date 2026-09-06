# GamePath relay deployment

Run the installer from a GamePath repository checkout on Debian 13:

```bash
sudo bash deploy/install-relay.sh \
  --port 51821 \
  --client-name my-windows-pc \
  --enrollment-output /root/my-windows-pc.enroll
```

The installer builds the Rust relay, configures IP forwarding and an isolated
nftables ruleset, installs a hardened systemd service, and creates one unique
client enrollment file. Running it again updates the binary and preserves all
existing client secrets.

Download the `.enroll` file over SSH, import it in the GamePath relay dialog,
and delete the downloaded plaintext file after import. The Windows client stores
the token with Electron `safeStorage`.

To add another client later:

```bash
sudo gamepath-relay enroll \
  --name second-pc \
  --clients-dir /etc/gamepath/clients \
  --output /root/second-pc.enroll
sudo systemctl restart gamepath-relay
```

Each token contains a random 128-bit client ID, a random 256-bit pre-shared key,
and an assigned address in `10.203.0.0/24`. Packet payloads use directional
HKDF-SHA256 session keys and ChaCha20-Poly1305 authentication. Tokens and server
records are never committed to Git.
