import { useState } from 'react'

export default function SearchForm({ onSubmit, loading }) {
  const [owner,    setOwner]    = useState('')
  const [repo,     setRepo]     = useState('')
  const [prNumber, setPrNumber] = useState('')
  const [runLlm,   setRunLlm]   = useState(true)

  function handleSubmit(e) {
    e.preventDefault()
    if (!owner || !repo || !prNumber) return
    onSubmit({ owner: owner.trim(), repo: repo.trim(), prNumber: prNumber.trim(), runLlm })
  }

  const inputClass =
    'bg-surface border border-border rounded-lg px-3 py-2.5 text-sm text-text ' +
    'placeholder:text-muted focus:outline-none focus:border-indigo-500 transition-colors w-full'

  return (
    <form onSubmit={handleSubmit} className="panel p-6 flex flex-col gap-5">
      <div>
        <h1 className="text-lg font-semibold text-text">PR Risk Analyst</h1>
        <p className="text-sm text-subtle mt-1">
          Analyze any GitHub pull request for security risk, CVE exposure, and blast radius
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="flex flex-col gap-1.5">
          <label className="label">Owner</label>
          <input className={inputClass} placeholder="argoproj" value={owner} onChange={e => setOwner(e.target.value)} required />
        </div>
        <div className="flex flex-col gap-1.5">
          <label className="label">Repository</label>
          <input className={inputClass} placeholder="argo-workflows" value={repo} onChange={e => setRepo(e.target.value)} required />
        </div>
        <div className="flex flex-col gap-1.5">
          <label className="label">PR Number</label>
          <input className={inputClass} placeholder="13021" type="number" min="1" value={prNumber} onChange={e => setPrNumber(e.target.value)} required />
        </div>
      </div>

      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2.5 cursor-pointer select-none">
          <div
            role="checkbox"
            aria-checked={runLlm}
            tabIndex={0}
            onClick={() => setRunLlm(v => !v)}
            onKeyDown={e => e.key === ' ' && setRunLlm(v => !v)}
            className={`w-9 h-5 rounded-full transition-colors relative cursor-pointer ${runLlm ? 'bg-indigo-600' : 'bg-border'}`}
          >
            <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${runLlm ? 'translate-x-4' : 'translate-x-0.5'}`} />
          </div>
          <span className="text-sm text-subtle">AI explanation</span>
        </label>

        <button className="btn-primary" disabled={loading}>
          {loading ? 'Analyzing…' : 'Analyze PR'}
        </button>
      </div>
    </form>
  )
}