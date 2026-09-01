import { useState, type ReactNode } from 'react'
import { Icon } from './icons'

// Always returns a string. FastAPI's `detail` is a string for HTTPException but
// a list of error objects for 422s, and a dev-proxy failure yields a plain-text
// body — rendering either of those raw puts "[object Object]" in a banner.
export const extractApiError = (e: unknown, fallback: string): string => {
  const err = e as {
    response?: { data?: unknown; status?: number }
    message?: string
  }
  const data = err?.response?.data
  if (typeof data === 'string' && data.trim()) return data.trim()
  const detail = (data as { detail?: unknown } | undefined)?.detail
  if (typeof detail === 'string' && detail) return detail
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((d) => (d as { msg?: string })?.msg)
      .filter((m): m is string => Boolean(m))
    if (msgs.length) return msgs.join('; ')
  }
  return err?.message || fallback
}

export const Banner = ({ kind, children }: { kind: 'err' | 'ok'; children: ReactNode }) => (
  <div className={`settings-banner ${kind}`}>
    <Icon name={kind === 'err' ? 'alert' : 'check2'} size={14} /> {children}
  </div>
)

// `saving` deliberately stays true on success so the panel can unmount on refetch
// without flashing the button back; it resets only on error so the user can retry.
export const useSaveAction = ({ onSaved }: { onSaved: () => void }) => {
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const run = async (task: () => Promise<void>, fallback: string) => {
    setSaving(true)
    setError(null)
    try {
      await task()
      onSaved()
    } catch (e) {
      setError(extractApiError(e, fallback))
      setSaving(false)
    }
  }
  return { saving, error, run }
}

export const StepFooter = ({
  onCancel,
  saving,
  onPrimary,
  primaryLabel,
  busyLabel,
  primaryDisabled,
}: {
  onCancel: () => void
  saving: boolean
  onPrimary: () => void
  primaryLabel: string
  busyLabel: string
  primaryDisabled?: boolean
}) => (
  <div className="flex justify-end gap-2.5 mt-2">
    <button className="btn ghost" onClick={onCancel} disabled={saving}>
      Cancel
    </button>
    <button className="btn primary" onClick={onPrimary} disabled={saving || primaryDisabled}>
      {saving ? busyLabel : primaryLabel}
    </button>
  </div>
)
