# GamePath relay deployment

Run the installer from a GamePath repository checkout on Debian 13 or newer,
or Ubuntu 22.04 or newer:

```bash
sudo bash deploy/install-relay.sh \
  --port 51821 \
  --client-name my-windows-pc \
  --enrollment-output /root/my-windows-pc.enroll
```

The installer builds the Rust relay, configures IP forwarding and an isolated
nftables ruleset, installs a hardened systemd service, and creates one unique
client enrollment file. Running it again updates the binary and preserves all
existing client secrets. Debian uses its packaged Rust compiler; Ubuntu uses an
isolated, pinned Rust toolchain under `/var/cache/gamepath` because older Ubuntu
LTS repositories do not provide the Rust 2024 edition compiler required by the
relay.

Download the `.enroll` file over SSH, import it in the GamePath relay dialog,
and delete the downloaded plaintext file after import. The Windows client stores
the token with Electron `safeStorage`.

To add another client later:

```bash
sudo flock -x /var/lock/gamepath-enrollment.lock gamepath-relay enroll \
  --name second-pc \
  --clients-dir /etc/gamepath/clients \
  --output /root/second-pc.enroll
sudo chmod 0640 /etc/gamepath/clients/second-pc.json
sudo chown root:gamepath /etc/gamepath/clients/second-pc.json
```

Each token contains a random 128-bit client ID, a random 256-bit pre-shared key,
and an assigned address in `10.203.0.0/24`. Packet payloads use directional
HKDF-SHA256 session keys and ChaCha20-Poly1305 authentication. Tokens and server
records are never committed to Git.

For sharing from the Windows UI, open **Game → Connection → Share**
on a configured relay. Enter a friend name and the VPS SSH login, then create
the invitation. GamePath enrolls a fresh client without replacing your own
credential. Copy the invitation link or save its `.gprelay` file and send it
privately to that friend. New clients are loaded automatically, without
restarting the relay or interrupting existing sessions. For older relays,
use **More → Update VPS** once between games to install this feature; updates preserve
existing client credentials. Sharing checks the running relay and refuses to
restart an older version automatically.

The recipient opens **Import shared relay** on the Connection tab, imports the
link from the clipboard or selects the file, reviews the endpoint, and clicks
**Add relay**. Links are imported inside GamePath; clicking them in a browser
does not launch the app. No website or VPS SSH login is needed to import.
Importing adds a relay without changing an existing selected relay or running
session. Select it and use Relay mode with your own VPN/proxy nodes.

Each invitation is reusable access for one client, with no automatic expiry;
create separate invitations for separate PCs. Copy/save is available in the
creation dialog for one hour. Save or send it before closing that dialog.
Delete the plaintext file after import. Invitations are exported by Electron's
main process; the renderer receives only the invitation ID and public metadata.

To remove someone else's access, choose **More → Manage access** on that relay and
sign in with the VPS's root or sudo SSH account. The dialog lists enrolled
clients by name, tunnel address, and client ID. Select **Revoke**, review the
specific client, and confirm **Revoke access**. Their sessions stop on the next
registry refresh; their old invitation no longer works. Other sessions keep
running. The local PC's recognized credential is marked **This PC** and cannot
be revoked from this dialog. Closing the dialog or signing out closes SSH;
administrative connections also expire after 15 minutes. Passwords are never
saved. Older relay binaries require a one-time update to expose these commands.

The equivalent server commands are:

```bash
sudo gamepath-relay clients --clients-dir /etc/gamepath/clients
sudo flock -x /var/lock/gamepath-enrollment.lock gamepath-relay revoke \
  --client-id CLIENT_ID --clients-dir /etc/gamepath/clients
```

Client listing returns only IDs, names and tunnel addresses, never keys. New
invitations store the friend name as a label; older invitations retain their
original generated names. Revocation records a key-free `.revoked` address
reservation before deleting the exact client record, so a newly enrolled client
cannot inherit late NAT replies belonging to a revoked client. Reservations
survive relay restarts and count against the subnet's 253 lifetime client
addresses; they are not automatically reclaimed. Keep these files when updating
or backing up the relay. Manual deletion of a client JSON file bypasses this
reservation, so use **Manage access** or `gamepath-relay revoke` instead.

The relay refreshes client records once per second, reading and validating them
outside the packet-processing lock. Unchanged clients retain their session keys,
replay windows, path endpoints, sequence counters, and repair buffers. Removing
a client record revokes only that client on the next refresh; changing its key
or assigned address discards only its sessions. An unreadable or invalid snapshot
leaves the previous registry active and reports a bounded warning. Client
records must remain readable by the `gamepath` group. Reusing an enrollment name
is rejected instead of overwriting someone else's credential.

The Windows client's **Auto-configure VPS** action performs this deployment over
SSH and imports the generated enrollment directly into Windows secure storage.
Its **Remove VPS** action runs `deploy/uninstall-relay.sh`, which removes the
GamePath service, nftables tables, configuration, enrolled clients, binary, and
service account. The SSH password is required for each operation and is not saved.
