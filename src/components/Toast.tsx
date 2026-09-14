import { CircleCheck, CircleX, Info, TriangleAlert, X } from 'lucide-react'

export type NoticeKind = 'success' | 'info' | 'warning' | 'error'
export type Notice = { message: string; kind: NoticeKind }
/** Reports a result to the user; defaults to a neutral, non-alarming tone. */
export type Notify = (message: string, kind?: NoticeKind) => void

const noticeIcons = { success: CircleCheck, info: Info, warning: TriangleAlert, error: CircleX }
const noticeLabels = {
  success: 'Success',
  info: 'Information',
  warning: 'Attention needed',
  error: 'Something went wrong',
}

export function Toast({ notice, onDismiss }: { notice: Notice; onDismiss: () => void }) {
  const Icon = noticeIcons[notice.kind]
  return (
    <div
      className={`toast toast-${notice.kind}`}
      role={notice.kind === 'error' ? 'alert' : 'status'}
      aria-atomic="true"
    >
      <Icon size={21} aria-hidden="true" />
      <div className="toast-content">
        <strong>{noticeLabels[notice.kind]}</strong>
        <span>{notice.message}</span>
      </div>
      <button type="button" aria-label="Dismiss notification" onClick={onDismiss}>
        <X size={18} aria-hidden="true" />
      </button>
    </div>
  )
}

/** Turns anything thrown into the sentence a toast can show. */
export const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error))
