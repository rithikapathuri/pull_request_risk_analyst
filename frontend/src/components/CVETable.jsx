const SEVERITY_STYLE = {
    critical: 'text-red-400',
    high:     'text-orange-400',
    medium:   'text-yellow-400',
    low:      'text-green-400',
    info:     'text-indigo-400',
  }
  
  export default function CVETable({ dependencyRisks }) {
    const allCves = dependencyRisks.flatMap(dep =>
      dep.cves.map(cve => ({ ...cve, is_new: dep.is_new }))
    )
  
    if (allCves.length === 0) {
      return (
        <div className="panel p-6">
          <span className="label">CVE Findings</span>
          <p className="text-sm text-muted mt-3">No known vulnerabilities found in dependencies</p>
        </div>
      )
    }
  
    return (
      <div className="panel flex flex-col">
        <div className="px-6 pt-6 pb-4 flex items-center justify-between">
          <span className="label">CVE Findings</span>
          <span className="text-xs text-muted">{allCves.length} found</span>
        </div>
  
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-t border-border">
                <th className="label text-left px-6 py-2">CVE</th>
                <th className="label text-left px-4 py-2">Package</th>
                <th className="label text-left px-4 py-2">CVSS</th>
                <th className="label text-left px-4 py-2">Reachable</th>
                <th className="label text-left px-4 py-2">Description</th>
              </tr>
            </thead>
            <tbody>
              {allCves.map((cve, i) => (
                <tr key={i} className="border-t border-border hover:bg-white/[0.02] transition-colors">
                  <td className="px-6 py-3 font-mono text-xs whitespace-nowrap">
                    <a
                      href={`https://osv.dev/vulnerability/${cve.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`hover:underline ${SEVERITY_STYLE[cve.severity] || 'text-text'}`}
                    >
                      {cve.cve_id}
                    </a>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-subtle whitespace-nowrap">
                    {cve.package}@{cve.installed_version}
                    {cve.is_new && <span className="ml-2 text-yellow-400">new</span>}
                  </td>
                  <td className={`px-4 py-3 font-mono text-xs ${SEVERITY_STYLE[cve.severity] || 'text-text'}`}>
                    {cve.cvss_score > 0 ? cve.cvss_score.toFixed(1) : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {cve.is_reachable === null
                      ? <span className="text-muted">unknown</span>
                      : cve.is_reachable
                      ? <span className="text-red-400">yes</span>
                      : <span className="text-green-400">no</span>}
                  </td>
                  <td className="px-4 py-3 text-xs text-subtle max-w-[260px] truncate">
                    {cve.description || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )
  }