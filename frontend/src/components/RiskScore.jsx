const LEVEL_COLOR = {
    critical: { ring: '#ef4444', text: 'text-red-400' },
    high:     { ring: '#f97316', text: 'text-orange-400' },
    medium:   { ring: '#eab308', text: 'text-yellow-400' },
    low:      { ring: '#22c55e', text: 'text-green-400' },
    info:     { ring: '#6366f1', text: 'text-indigo-400' },
  }
  
  function Arc({ score, color }) {
    const r            = 52
    const circumference = 2 * Math.PI * r
    const filled       = (score / 100) * circumference
  
    return (
      <svg width="128" height="128" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r={r} fill="none" stroke="#1e2636" strokeWidth="10" />
        <circle
          cx="64" cy="64" r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${filled} ${circumference}`}
          strokeLinecap="round"
          transform="rotate(-90 64 64)"
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
      </svg>
    )
  }
  
  function Bar({ label, value, color }) {
    return (
      <div className="flex flex-col gap-1">
        <div className="flex justify-between items-center">
          <span className="text-xs text-subtle capitalize">{label.replace(/_/g, ' ')}</span>
          <span className="text-xs font-mono text-text">{value.toFixed(0)}</span>
        </div>
        <div className="h-1 bg-border rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{ width: `${value}%`, backgroundColor: color }}
          />
        </div>
      </div>
    )
  }
  
  export default function RiskScore({ breakdown }) {
    const level  = breakdown.risk_level
    const colors = LEVEL_COLOR[level] || LEVEL_COLOR.info
    const score  = breakdown.final_score
  
    const components = [
      { label: 'change_severity',  value: breakdown.change_severity },
      { label: 'blast_radius',     value: breakdown.blast_radius },
      { label: 'security_signals', value: breakdown.security_signals },
      { label: 'dependency_risk',  value: breakdown.dependency_risk },
    ]
  
    return (
      <div className="panel p-6 flex flex-col gap-5">
        <span className="label">Risk Score</span>
        <div className="flex items-center gap-6">
          <div className="relative flex-shrink-0">
            <Arc score={score} color={colors.ring} />
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-semibold text-text">{score.toFixed(0)}</span>
              <span className={`text-xs font-medium uppercase ${colors.text}`}>{level}</span>
            </div>
          </div>
          <div className="flex-1 flex flex-col gap-2.5">
            {components.map(c => (
              <Bar key={c.label} label={c.label} value={c.value} color={colors.ring} />
            ))}
          </div>
        </div>
      </div>
    )
  }