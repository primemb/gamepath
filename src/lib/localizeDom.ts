import type { Language } from './language'
import { translatePersian } from './persian'

type Source = { english: string; shown: string }
const textSources = new WeakMap<Text, Source>()
const attributeSources = new WeakMap<Element, Map<string, Source>>()
const attributes = ['title', 'placeholder', 'aria-label', 'alt']
let language: Language = 'en'

function translated(value: string) {
  const normalized = value.replace(/\s+/g, ' ').trim()
  if (!normalized) return value
  const match = translatePersian(normalized)
  if (match === normalized || language === 'en') return value
  const leading = value.match(/^\s*/)?.[0] ?? ''
  const trailing = value.match(/\s*$/)?.[0] ?? ''
  return `${leading}${match}${trailing}`
}

function localizeText(node: Text) {
  const current = node.nodeValue ?? ''
  const previous = textSources.get(node)
  const english = previous && current === previous.shown ? previous.english : current
  const shown = translated(english)
  textSources.set(node, { english, shown })
  if (current !== shown) node.nodeValue = shown
}

function localizeAttribute(element: Element, name: string) {
  const current = element.getAttribute(name)
  if (current === null) return
  const sources = attributeSources.get(element) ?? new Map<string, Source>()
  const previous = sources.get(name)
  const english = previous && current === previous.shown ? previous.english : current
  const shown = translated(english)
  sources.set(name, { english, shown })
  attributeSources.set(element, sources)
  if (current !== shown) element.setAttribute(name, shown)
}

function visit(root: Node) {
  if (root.nodeType === Node.TEXT_NODE) {
    localizeText(root as Text)
    return
  }
  if (root.nodeType !== Node.ELEMENT_NODE) return
  const element = root as Element
  if (element.closest('[data-no-translate],script,style')) return
  for (const name of attributes) localizeAttribute(element, name)
  for (const child of element.childNodes) visit(child)
}

export function observeLanguage(root: HTMLElement, selected: Language) {
  language = selected
  document.documentElement.lang = selected
  document.documentElement.dir = selected === 'fa' ? 'rtl' : 'ltr'
  visit(root)
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'characterData') visit(mutation.target)
      else if (mutation.type === 'attributes') localizeAttribute(mutation.target as Element, mutation.attributeName!)
      else for (const node of mutation.addedNodes) visit(node)
    }
  })
  observer.observe(root, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: attributes,
  })
  return () => observer.disconnect()
}

export function tr(value: string) {
  return language === 'fa' ? translatePersian(value) : value
}
