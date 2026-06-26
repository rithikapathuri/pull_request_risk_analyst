import { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'

cytoscape.use(dagre)

const NODE_COLOR = {
  critical:  '#ef4444',
  secondary: '#f97316',
  low:       '#4b5675',
}

const CHANGED_COLOR  = '#6366f1'
const BG_COLOR       = '#0f1117'
const TEXT_COLOR     = '#8b95b0'
const EDGE_COLOR     = '#2a3347'
const EDGE_HIGHLIGHT = '#6366f1'

function buildStyles() {
  return [
    {
      selector: 'node',
      style: {
        label:              'data(label)',
        'text-valign':      'center',
        'text-halign':      'center',
        'font-family':      'JetBrains Mono, Menlo, monospace',
        'font-size':        '10px',
        color:              TEXT_COLOR,
        'background-color': NODE_COLOR.low,
        'border-width':     1,
        'border-color':     '#1e2636',
        width:              'label',
        height:             28,
        padding:            '0 10px',
        shape:              'roundrectangle',
      },
    },
    {
      selector: 'node[sensitivity = "critical"]',
      style: {
        'background-color': '#1f0a0a',
        'border-color':     NODE_COLOR.critical,
        'border-width':     1.5,
        color:              NODE_COLOR.critical,
      },
    },
    {
      selector: 'node[sensitivity = "secondary"]',
      style: {
        'background-color': '#1a0e06',
        'border-color':     NODE_COLOR.secondary,
        'border-width':     1.5,
        color:              NODE_COLOR.secondary,
      },
    },
    {
      selector: 'node[?is_changed]',
      style: {
        'background-color': '#0d0e1f',
        'border-color':     CHANGED_COLOR,
        'border-width':     2,
        color:              CHANGED_COLOR,
      },
    },
    {
      selector: 'node:selected',
      style: { 'border-width': 2, 'border-color': '#818cf8' },
    },
    {
      selector: 'edge',
      style: {
        width:                1,
        'line-color':         EDGE_COLOR,
        'target-arrow-color': EDGE_COLOR,
        'target-arrow-shape': 'triangle',
        'curve-style':        'bezier',
        'arrow-scale':        0.8,
      },
    },
    {
      selector: 'edge:selected',
      style: { 'line-color': EDGE_HIGHLIGHT, 'target-arrow-color': EDGE_HIGHLIGHT },
    },
  ]
}

export default function CallGraph({ graphData, loading, error }) {
  const containerRef = useRef(null)
  const cyRef        = useRef(null)
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    if (!graphData || !containerRef.current || graphData.nodes.length === 0) return

    cyRef.current?.destroy()

    const cy = cytoscape({
      container: containerRef.current,
      elements:  [...graphData.nodes, ...graphData.edges],
      style:     buildStyles(),
      layout: {
        name:    'dagre',
        rankDir: 'LR',
        nodeSep: 40,
        rankSep: 80,
        padding: 24,
        animate: false,
      },
      userZoomingEnabled:  true,
      userPanningEnabled:  true,
      boxSelectionEnabled: false,
      minZoom: 0.2,
      maxZoom: 3,
    })

    cy.on('tap', 'node', e => {
      const d = e.target.data()
      setSelected({ label: d.label, filename: d.filename, changed: d.is_changed, sensitivity: d.sensitivity })
    })

    cy.on('tap', e => { if (e.target === cy) setSelected(null) })

    cyRef.current = cy
    return () => { cy.destroy(); cyRef.current = null }
  }, [graphData])

  return (
    <div className="panel flex flex-col" style={{ minHeight: 420 }}>
      <div className="px-6 pt-6 pb-4 flex items-center justify-between flex-shrink-0">
        <span className="label">Call Graph</span>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-3 text-xs text-muted">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-sm bg-indigo-500/80 inline-block" /> changed
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-sm bg-red-500/80 inline-block" /> critical
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-sm bg-orange-500/80 inline-block" /> secondary
            </span>
          </div>
          <button onClick={() => cyRef.current?.fit(undefined, 24)} className="btn-ghost text-xs py-1 px-2">
            Reset view
          </button>
        </div>
      </div>

      <div className="relative flex-1 border-t border-border" style={{ minHeight: 340 }}>
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-sm text-muted">Building graph…</span>
          </div>
        )}
        {error && (
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-sm text-muted">{error}</span>
          </div>
        )}
        {!loading && !error && graphData?.nodes.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-sm text-muted">No function nodes found in changed files</span>
          </div>
        )}

        <div ref={containerRef} className="absolute inset-0" style={{ background: BG_COLOR }} />

        {selected && (
          <div className="absolute bottom-4 left-4 panel px-4 py-3 text-xs flex flex-col gap-1 max-w-xs z-10">
            <span className="font-mono text-text">{selected.label}</span>
            <span className="text-muted truncate">{selected.filename}</span>
            <div className="flex gap-2 mt-0.5">
              {selected.changed && <span className="text-indigo-400">changed</span>}
              {selected.sensitivity !== 'low' && (
                <span className={selected.sensitivity === 'critical' ? 'text-red-400' : 'text-orange-400'}>
                  {selected.sensitivity}
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}