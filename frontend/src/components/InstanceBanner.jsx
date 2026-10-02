import { useEffect, useState } from 'react'
import { instanceService } from '../services'

const BASE_TITLE = document.title

/**
 * A strip across every screen, sign-in included, naming a non-production
 * deployment ("Préproduction"), and the same label in the tab title.
 *
 * A staging environment restored from production looks exactly like it, down
 * to the accounts: without this, a risk accepted there by mistake looks done.
 * The label comes from the API (INSTANCE_BANNER) rather than the build,
 * because staging and production run the same frontend image.
 */
export default function InstanceBanner() {
  const [banner, setBanner] = useState(null)

  useEffect(() => {
    let cancelled = false
    instanceService
      .get()
      .then((res) => {
        if (!cancelled) setBanner(res.data?.banner || null)
      })
      .catch(() => {
        /* no banner is the production case: never block the app on it */
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    document.title = [banner, BASE_TITLE].filter(Boolean).join(' · ')
  }, [banner])

  if (!banner) return null
  return (
    <div role="status" className="instance-banner">
      {banner}
    </div>
  )
}
