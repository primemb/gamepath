import game from '../assets/illustrations/game.webp'
import vpn from '../assets/illustrations/vpn.webp'
import statistics from '../assets/illustrations/statistics.webp'
import gamerGirl from '../assets/illustrations/gamer-girl.webp'
import vpnGirl from '../assets/illustrations/vpn-girl.webp'
import '../illustrations.css'

const illustrations = { game, vpn, statistics, 'gamer-girl': gamerGirl, 'vpn-girl': vpnGirl }

export function AppIllustration({
  variant,
  className = '',
  loading = 'lazy',
}: {
  variant: keyof typeof illustrations
  className?: string
  loading?: 'eager' | 'lazy'
}) {
  return (
    <img
      className={`app-illustration ${className}`}
      src={illustrations[variant]}
      alt=""
      aria-hidden="true"
      width={384}
      height={384}
      loading={loading}
      decoding="async"
      draggable={false}
    />
  )
}
