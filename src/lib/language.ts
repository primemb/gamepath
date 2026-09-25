export type Language = 'en' | 'fa'

const storageKey = 'gamepath-language'

export function savedLanguage(): Language {
  try {
    const stored = window.localStorage.getItem(storageKey)
    return stored === 'fa' || (stored === null && window.navigator.language.toLowerCase().startsWith('fa'))
      ? 'fa'
      : 'en'
  } catch {
    return 'en'
  }
}

export function saveLanguage(language: Language) {
  try {
    window.localStorage.setItem(storageKey, language)
  } catch {
    // The selection still works for this window when storage is unavailable.
  }
}
