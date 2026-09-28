import { useEffect, useState, type FormEvent } from 'react'
import { Eye, EyeOff, KeyRound } from 'lucide-react'
import { errorMessage } from './Toast'
import type { LanProxySettings, LanProxySettingsInput } from '../types'

export function LanProxySettingsForm({
  settings,
  onSave,
}: {
  settings: LanProxySettings
  onSave: (input: LanProxySettingsInput) => Promise<void>
}) {
  const [port, setPort] = useState(String(settings.port))
  const [username, setUsername] = useState(settings.username)
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<{ field: 'port' | 'login' | 'form'; message: string } | null>(null)

  useEffect(() => {
    setPort(String(settings.port))
    setUsername(settings.username)
  }, [settings.port, settings.username])

  const portNumber = Number(port)
  const portInvalid = !Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535
  const changed =
    portNumber !== settings.port || username.trim() !== settings.username || (username.trim() !== '' && password !== '')

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (portInvalid) {
      setError({ field: 'port', message: 'Choose a port from 1 to 65535.' })
      return
    }
    if (username.trim() && !password && !settings.hasPassword) {
      setError({ field: 'login', message: 'Enter a password, or leave the username empty to turn the login off.' })
      return
    }
    setSaving(true)
    setError(null)
    try {
      await onSave({ port: portNumber, username: username.trim(), password: password || undefined })
      setPassword('')
    } catch (reason) {
      const message = errorMessage(reason)
      setError({
        field: /port/i.test(message) ? 'port' : /password|username/i.test(message) ? 'login' : 'form',
        message,
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="sharing-card sharing-settings" onSubmit={submit} aria-labelledby="sharing-settings-title">
      <div className="sharing-card-head">
        <div>
          <span className="eyebrow">Settings</span>
          <h3 id="sharing-settings-title">Port and login</h3>
        </div>
        <span className={`status-pill ${settings.hasPassword ? 'online' : ''}`}>
          <i aria-hidden="true" />
          {settings.hasPassword ? 'Login on' : 'No login'}
        </span>
      </div>
      <label className="field-label">
        Port
        <input
          inputMode="numeric"
          value={port}
          onChange={(event) => setPort(event.target.value.replace(/\D/g, '').slice(0, 5))}
          aria-invalid={error?.field === 'port'}
          aria-describedby={error?.field === 'port' ? 'sharing-port-error' : 'sharing-port-help'}
        />
        {error?.field === 'port' ? (
          <small id="sharing-port-error" className="field-error">
            {error.message}
          </small>
        ) : (
          <small id="sharing-port-help">If another program holds this port, the next free one is used instead.</small>
        )}
      </label>
      <label className="field-label">
        <span className="field-title">
          Username <span className="optional">Optional</span>
        </span>
        <input
          value={username}
          autoComplete="off"
          onChange={(event) => setUsername(event.target.value)}
          placeholder="Leave empty for no login"
          aria-invalid={error?.field === 'login'}
          aria-describedby={error?.field === 'login' ? 'sharing-login-error' : undefined}
        />
      </label>
      <label className="field-label">
        Password
        <span className="password-field">
          <input
            type={showPassword ? 'text' : 'password'}
            value={password}
            autoComplete="new-password"
            disabled={!username.trim()}
            onChange={(event) => setPassword(event.target.value)}
            placeholder={settings.hasPassword ? 'Saved — type to replace' : 'Required with a username'}
            aria-invalid={error?.field === 'login'}
            aria-describedby={error?.field === 'login' ? 'sharing-login-error' : undefined}
          />
          <button
            type="button"
            className="icon-button"
            onClick={() => setShowPassword(!showPassword)}
            disabled={!username.trim()}
            aria-label={showPassword ? 'Hide password' : 'Show password'}
            aria-pressed={showPassword}
          >
            {showPassword ? <EyeOff size={15} aria-hidden="true" /> : <Eye size={15} aria-hidden="true" />}
          </button>
        </span>
        {error?.field === 'login' && (
          <small id="sharing-login-error" className="field-error">
            {error.message}
          </small>
        )}
      </label>
      {error?.field === 'form' && (
        <p className="field-error" role="alert">
          {error.message}
        </p>
      )}
      <div className="sharing-settings-actions">
        <small>
          <KeyRound size={12} aria-hidden="true" /> The password is encrypted by Windows and changes apply without
          reconnecting.
        </small>
        <button className="button primary" type="submit" disabled={saving || !changed}>
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>
    </form>
  )
}
