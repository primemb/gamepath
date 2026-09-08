import { useEffect, useState } from 'react'
import { hasFlag } from 'country-flag-icons'
import type { IpCountry } from './types'

export function CountryFlag({ countryCode, country }: { countryCode: string; country: string }) {
  const code = countryCode.toUpperCase()
  if (!hasFlag(code)) return null
  return <span className={`country-flag flag:${code}`} title={country} role="img" aria-label={country} />
}

export function IpCountryFlag({ target }: { target: string }) {
  const [location, setLocation] = useState<IpCountry | null>(null)

  useEffect(() => {
    let active = true
    setLocation(null)
    void window.gamepath
      ?.lookupIpCountry(target)
      .then((result) => {
        if (active) setLocation(result)
      })
      .catch(() => undefined)
    return () => {
      active = false
    }
  }, [target])

  return location ? <CountryFlag countryCode={location.countryCode} country={location.country} /> : null
}

export function AddressWithCountry({ value, suffix = '' }: { value: string; suffix?: string }) {
  return (
    <span className="address-with-country">
      <span>{value + suffix}</span>
      <IpCountryFlag target={value} />
    </span>
  )
}
