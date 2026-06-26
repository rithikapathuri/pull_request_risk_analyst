export default function PRMeta({ pr }) {
    const totalAdditions = pr.files.reduce((s, f) => s + f.additions, 0)
    const totalDeletions = pr.files.reduce((s, f) => s + f.deletions, 0)
  
    return (
      <div className="panel p-6 flex flex-col gap-3">
        <span className="label">Pull Request</span>
  
        <a
          href={`https://github.com/${pr.owner}/${pr.repo}/pull/${pr.number}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-base font-medium text-text hover:text-indigo-400 transition-colors leading-snug"
        >
          {pr.title}
        </a>
  
        <div className="flex flex-wrap gap-x-5 gap-y-1.5 text-sm text-subtle">
          <span><span className="text-muted">by </span>{pr.author}</span>
          <span><span className="text-muted">repo </span>{pr.owner}/{pr.repo}</span>
          <span><span className="text-muted">PR </span>#{pr.number}</span>
          <span><span className="text-muted">base </span>{pr.base_branch}</span>
        </div>
  
        <div className="flex gap-4 pt-1 text-sm font-mono">
          <span className="text-green-400">+{totalAdditions}</span>
          <span className="text-red-400">-{totalDeletions}</span>
          <span className="text-subtle">{pr.files.length} files</span>
        </div>
  
        {pr.new_dependencies.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            <span className="label w-full">New packages</span>
            {pr.new_dependencies.map(pkg => (
              <span
                key={pkg}
                className="text-xs font-mono bg-yellow-400/10 text-yellow-300 border border-yellow-400/20 px-2 py-0.5 rounded"
              >
                {pkg}
              </span>
            ))}
          </div>
        )}
      </div>
    )
  }