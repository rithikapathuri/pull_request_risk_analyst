import { useState, useCallback } from 'react'

const API = '/api/v1'

export function useAnalysis() {
  const [result, setResult]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)

  const analyze = useCallback(async ({ owner, repo, prNumber, runLlm }) => {
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch(`${API}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          owner,
          repo,
          pr_number: parseInt(prNumber, 10),
          run_llm: runLlm,
        }),
      })

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail || `Request failed (${res.status})`)
      }

      const data = await res.json()
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchGraphData = useCallback(async ({ owner, repo, prNumber }) => {
    const res = await fetch(`${API}/graph`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        owner,
        repo,
        pr_number: parseInt(prNumber, 10),
        run_llm: false,
      }),
    })
    if (!res.ok) throw new Error('Graph fetch failed')
    return res.json()
  }, [])

  return { result, loading, error, analyze, fetchGraphData }
}