const SEVERITY_STYLE = {
    critical: 'bg-red-400/10 text-red-400 border-red-400/20',
    high:     'bg-orange-400/10 text-orange-400 border-orange-400/20',
    medium:   'bg-yellow-400/10 text-yellow-400 border-yellow-400/20',
    low:      'bg-green-400/10 text-green-400 border-green-400/20',
    info:     'bg-indigo-400/10 text-indigo-400 border-indigo-400/20',
  }
  
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  
  function Badge({ level }) {
    return (
      <span className={`text-xs font-medium border px-1.5 py-0.5 rounded uppercase ${SEVERITY_STYLE[level] || SEVERITY_STYLE.info}`}>
        {level}
      </span>
    )
  }
  
  export default function SignalsTable({ summaries }) {
    if (!summaries || summaries.length === 0) {
      return (
        <div className="panel p-6">
          <span className="label">Security Signals</span>
          <p className="text-sm text-muted mt-3">No signals detected</p>
        </div>
      )
    }
  
    const sorted = [...summaries].sort((a, b) => {
      const aScore = (a.signal.is_deletion ? -10 : 0) + (SEVERITY_ORDER[a.signal.severity] ?? 5)
      const bScore = (b.signal.is_deletion ? -10 : 0) + (SEVERITY_ORDER[b.signal.severity] ?? 5)
      return aScore - bScore
    })
  
    return (
      <div className="panel flex flex-col">
        <div className="px-6 pt-6 pb-4 flex items-center justify-between">
          <span className="label">Security Signals</span>
          <span className="text-xs text-muted">{summaries.length} found</span>
        </div>
  
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-t border-border">
                <th className="label text-left px-6 py-2">Type</th>
                <th className="label text-left px-4 py-2">Severity</th>
                <th className="label text-left px-4 py-2">File</th>
                <th className="label text-left px-4 py-2">Snippet</th>
                <th className="label text-left px-4 py-2">Note</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((s, i) => {
                const sig = s.signal
                return (
                  <tr key={i} className="border-t border-border hover:bg-white/[0.02] transition-colors">
                    <td className="px-6 py-3 font-mono text-xs text-text whitespace-nowrap">
                      {sig.is_deletion && <span className="text-red-400 mr-1.5">— removed</span>}
                      {sig.signal_type}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <Badge level={sig.severity} />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-subtle max-w-[180px] truncate">
                      {sig.filename}{sig.line > 0 && <span className="text-muted">:{sig.line}</span>}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-subtle max-w-[240px] truncate">
                      {sig.snippet}
                    </td>
                    <td className="px-4 py-3 text-xs text-subtle max-w-[200px]">
                      {s.llm_verdict || (sig.is_ambiguous && !s.confirmed_risky
                        ? <span className="text-muted">cleared by AI</span>
                        : null)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    )
  }