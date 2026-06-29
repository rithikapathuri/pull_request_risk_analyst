import { useState, useCallback } from 'react'
import { useAnalysis } from './hooks/useAnalysis'
import SearchForm   from './components/SearchForm'
import PRMeta       from './components/PRMeta'
import RiskScore    from './components/RiskScore'
import AIPanel      from './components/AIPanel'
import SignalsTable from './components/SignalsTable'
import CVETable     from './components/CVETable'
import BlastRadius  from './components/BlastRadius'
import CallGraph    from './components/CallGraph'

export default function App() {
  const { result, loading, error, analyze, fetchGraphData } = useAnalysis()

  const [graphData,    setGraphData]    = useState(null)
  const [graphLoading, setGraphLoading] = useState(false)
  const [graphError,   setGraphError]   = useState(null)
  const [lastParams,   setLastParams]   = useState(null)

  const handleSubmit = useCallback(async (params) => {
    setLastParams(params)
    setGraphData(null)
    setGraphError(null)
    await analyze(params)
  }, [analyze])

  const handleLoadGraph = useCallback(async () => {
    if (!lastParams) return
    setGraphLoading(true)
    setGraphError(null)
    try {
      const data = await fetchGraphData(lastParams)
      setGraphData(data)
    } catch (e) {
      setGraphError(e.message)
    } finally {
      setGraphLoading(false)
    }
  }, [lastParams, fetchGraphData])

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-border px-6 py-4 flex items-center gap-3">
        <span className="text-sm font-semibold text-text">PR Risk Analyst</span>
        <span className="text-muted text-xs">·</span>
        <span className="text-xs text-muted">GitHub pull request security analysis</span>
      </header>

      <main className="flex-1 px-4 md:px-6 py-6 flex flex-col gap-4 max-w-7xl mx-auto w-full">
        <SearchForm onSubmit={handleSubmit} loading={loading} />

        {error && (
          <div className="panel px-5 py-4 text-sm text-red-400 border-red-400/20">
            {error}
          </div>
        )}

        {loading && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="panel p-6 h-40 animate-pulse">
                <div className="h-3 w-20 bg-border rounded mb-4" />
                <div className="h-4 w-3/4 bg-border rounded mb-2" />
                <div className="h-4 w-1/2 bg-border rounded" />
              </div>
            ))}
          </div>
        )}

        {result && !loading && (
          <>
            {/* PR info and risk score side by side — both compact */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <PRMeta pr={result.pr} />
              <RiskScore breakdown={result.risk_breakdown} />
            </div>

            {/* AI panel full width — content is too long for a column */}
            <AIPanel
              triage={result.triage}
              explanation={result.explanation}
              recommendations={result.recommendations}
            />

            <BlastRadius blastRadius={result.blast_radius} />
            <SignalsTable summaries={result.security_signal_summaries} />
            <CVETable dependencyRisks={result.dependency_risks} />

            <div className="flex flex-col gap-3">
              {!graphData && !graphLoading && (
                <div className="panel p-6 flex items-center justify-between">
                  <div>
                    <span className="label block mb-1">Dependency Graph</span>
                    <p className="text-sm text-muted">
                      Visualize file relationships and blast radius across changed files
                    </p>
                  </div>
                  <button className="btn-primary flex-shrink-0 ml-4" onClick={handleLoadGraph}>
                    Load graph
                  </button>
                </div>
              )}
              {(graphData || graphLoading || graphError) && (
                <CallGraph graphData={graphData} loading={graphLoading} error={graphError} />
              )}
            </div>
          </>
        )}
      </main>

      <footer className="border-t border-border px-6 py-3 text-xs text-muted">
        <span>PR Risk Analyst</span>
      </footer>
    </div>
  )
}