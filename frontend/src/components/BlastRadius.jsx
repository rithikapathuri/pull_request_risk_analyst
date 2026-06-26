function ImpactGroup({ label, nodes, color }) {
    if (!nodes || nodes.length === 0) return null
  
    return (
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <span className="label">{label}</span>
          <span className={`text-xs font-mono ${color}`}>{nodes.length}</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {nodes.map((node, i) => {
            const parts = node.split('::')
            const fn    = parts[parts.length - 1]
            const file  = parts.length > 1 ? parts[0].split('/').pop() : null
            return (
              <span
                key={i}
                title={node}
                className="font-mono text-xs px-2 py-1 rounded bg-border text-subtle hover:text-text transition-colors"
              >
                {file ? `${file} › ${fn}` : fn}
              </span>
            )
          })}
        </div>
      </div>
    )
  }
  
  export default function BlastRadius({ blastRadius }) {
    const total = blastRadius.total_affected
  
    if (total === 0) {
      return (
        <div className="panel p-6">
          <span className="label">Blast Radius</span>
          <p className="text-sm text-muted mt-3">No downstream impact detected</p>
        </div>
      )
    }
  
    return (
      <div className="panel p-6 flex flex-col gap-5">
        <div className="flex items-center justify-between">
          <span className="label">Blast Radius</span>
          <span className="text-xs text-muted">{total} node{total !== 1 ? 's' : ''} affected</span>
        </div>
        <ImpactGroup label="Critical Impact"   nodes={blastRadius.critical_impact}  color="text-red-400" />
        <ImpactGroup label="Secondary Impact"  nodes={blastRadius.secondary_impact} color="text-orange-400" />
        <ImpactGroup label="Low Impact"        nodes={blastRadius.low_impact}       color="text-subtle" />
      </div>
    )
  }