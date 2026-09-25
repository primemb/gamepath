import { Code2, Copy, ExternalLink, MessageCircle, Zap } from 'lucide-react'
import type { Notify } from '../components/Toast'

export function InfoView({ notify }: { notify: Notify }) {
  const copyDiscord = async () => {
    try {
      await navigator.clipboard.writeText('prime_lifesoul')
      notify('Discord username copied: prime_lifesoul', 'success')
    } catch {
      notify('Could not copy the username. You can add prime_lifesoul on Discord.', 'error')
    }
  }

  return (
    <section className="page-section">
      <div className="creator-card" aria-labelledby="creator-title">
        <div className="creator-heading">
          <span className="creator-mark">
            <Zap size={24} aria-hidden="true" />
          </span>
          <div>
            <span className="eyebrow">Behind GamePath</span>
            <h2 id="creator-title">Built by primemb</h2>
            <p>A better path to your next game.</p>
          </div>
          <span className="creator-badge">Creator</span>
        </div>
        <div className="creator-links">
          <a href="https://github.com/primemb/gamepath" target="_blank" rel="noopener noreferrer">
            <Code2 size={20} aria-hidden="true" />
            <span>
              <strong>GamePath on GitHub</strong>
              <small>primemb / gamepath</small>
            </span>
            <ExternalLink size={16} aria-hidden="true" />
          </a>
          <button type="button" onClick={copyDiscord} aria-label="Copy Discord username prime_lifesoul">
            <MessageCircle size={20} aria-hidden="true" />
            <span>
              <strong>Connect on Discord</strong>
              <small>prime_lifesoul</small>
            </span>
            <Copy size={16} aria-hidden="true" />
          </button>
        </div>
        <p className="creator-legal">&copy; {new Date().getFullYear()} primemb. GamePath.</p>
      </div>
    </section>
  )
}
