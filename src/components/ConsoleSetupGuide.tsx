import { useState, type ReactNode } from 'react'
import { Info } from 'lucide-react'

type Platform = 'playstation' | 'switch' | 'xbox' | 'client'

const platforms: Array<[Platform, string]> = [
  ['playstation', 'PlayStation'],
  ['switch', 'Nintendo Switch'],
  ['xbox', 'Xbox'],
  ['client', 'PC and phone'],
]

/**
 * Where each device keeps its proxy setting, and what that setting can carry.
 *
 * Console proxy settings speak HTTP, which only carries TCP, and saying so is
 * the point of the note: a player who expects in-game UDP to follow would
 * otherwise blame the tunnel.
 */
export function ConsoleSetupGuide({ address, port, login }: { address: string; port: number; login: boolean }) {
  const [platform, setPlatform] = useState<Platform>('playstation')
  const server = (
    <code data-no-translate>
      {address}:{port}
    </code>
  )
  const steps: Record<Platform, ReactNode[]> = {
    playstation: [
      'Settings → Network → Settings → Set Up Internet Connection.',
      'Highlight your network, press Options, then choose Advanced Settings.',
      <>Set Proxy Server to Use, then enter {server} as the address and port.</>,
    ],
    switch: [
      'System Settings → Internet → Internet Settings, then choose your network.',
      'Change Settings → Proxy Settings → On.',
      <>
        Enter {server} as the server and port{login ? ', and turn on Authentication with your login' : ''}.
      </>,
    ],
    xbox: [
      'Xbox has no proxy setting of its own.',
      'Connect it through a router or device that can forward its traffic to a SOCKS5 proxy, such as a router running a tun2socks or Clash client.',
      <>Point that client at {server} with SOCKS5 and UDP enabled.</>,
    ],
    client: [
      'Use any SOCKS5 client, or the system proxy setting for apps that only need TCP.',
      <>
        Choose SOCKS5, enter {server}
        {login ? ' and your login' : ''}.
      </>,
      'Turn on UDP relay and remote DNS in the client, so games and name lookups use the tunnel too.',
    ],
  }
  const httpOnly = platform === 'playstation' || platform === 'switch'

  return (
    <section className="sharing-card sharing-guide" aria-labelledby="sharing-guide-title">
      <div className="sharing-card-head">
        <div>
          <span className="eyebrow">Setup</span>
          <h3 id="sharing-guide-title">Connect a device</h3>
        </div>
      </div>
      <div className="segmented-control sharing-platforms" role="tablist" aria-label="Device type">
        {platforms.map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={platform === id}
            className={platform === id ? 'active' : ''}
            onClick={() => setPlatform(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <ol className="sharing-steps" role="tabpanel">
        {steps[platform].map((step, index) => (
          <li key={index}>
            <span aria-hidden="true">{index + 1}</span>
            <p>{step}</p>
          </li>
        ))}
      </ol>
      <p className="sharing-note">
        <Info size={14} aria-hidden="true" />
        {httpOnly
          ? 'A console proxy setting uses HTTP, which carries TCP: sign-in, the store, downloads and most matchmaking. Game traffic sent over UDP still leaves directly. For full UDP, use a SOCKS5 client on a router in front of the console.'
          : 'SOCKS5 carries TCP and UDP. Every connection, datagram and name lookup goes through the session, whatever the split-tunnel rules say.'}
      </p>
    </section>
  )
}
