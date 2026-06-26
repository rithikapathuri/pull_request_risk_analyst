const CATEGORY_LABELS = {
    injection:      'Injection',
    auth:           'Authentication',
    supply_chain:   'Supply Chain',
    crypto:         'Cryptography',
    access_control: 'Access Control',
    data_exposure:  'Data Exposure',
    config:         'Configuration',
    logic:          'Business Logic',
    low_risk:       'Low Risk',
  }
  
  const CONFIDENCE_STYLE = {
    high:   'text-green-400',
    medium: 'text-yellow-400',
    low:    'text-red-400',
  }
  
  function Section({ title, children }) {
    return (
      <div className="flex flex-col gap-2">
        <span className="label">{title}</span>
        {children}
      </div>
    )
  }
  
  export default function AIPanel({ triage, explanation, recommendations }) {
    if (!triage && !explanation && !recommendations) {
      return (
        <div className="panel p-6">
          <span className="label">AI Analysis</span>
          <p className="text-sm text-muted mt-3">
            Run with AI explanation enabled to see triage, risk explanation, and fix recommendations
          </p>
        </div>
      )
    }
  
    return (
      <div className="panel p-6 flex flex-col gap-6">
        <span className="label">AI Analysis</span>
  
        {triage && (
          <Section title="Risk Category">
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium text-text">
                {CATEGORY_LABELS[triage.primary_risk_category] || triage.primary_risk_category}
              </span>
              <span className={`text-xs ${CONFIDENCE_STYLE[triage.confidence] || 'text-subtle'}`}>
                {triage.confidence} confidence
              </span>
            </div>
            <p className="text-sm text-subtle leading-relaxed">{triage.reasoning}</p>
          </Section>
        )}
  
        {explanation && (
          <>
            <Section title="Summary">
              <p className="text-sm text-subtle leading-relaxed">{explanation.summary}</p>
            </Section>
  
            {explanation.what_could_break.length > 0 && (
              <Section title="What Could Break">
                <ul className="flex flex-col gap-1.5">
                  {explanation.what_could_break.map((item, i) => (
                    <li key={i} className="flex gap-2 text-sm text-subtle">
                      <span className="text-red-400 mt-0.5 flex-shrink-0">—</span>
                      <span className="leading-relaxed">{item}</span>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
  
            <Section title="Attack Surface">
              <p className="text-sm text-subtle leading-relaxed">{explanation.attack_surface}</p>
            </Section>
  
            <Section title="Severity Justification">
              <p className="text-sm text-subtle leading-relaxed">{explanation.severity_justification}</p>
            </Section>
          </>
        )}
  
        {recommendations && (
          <>
            {recommendations.immediate_fixes.length > 0 && (
              <Section title="Fix Before Merging">
                <ul className="flex flex-col gap-1.5">
                  {recommendations.immediate_fixes.map((fix, i) => (
                    <li key={i} className="flex gap-2 text-sm text-subtle">
                      <span className="text-orange-400 mt-0.5 flex-shrink-0">—</span>
                      <span className="leading-relaxed">{fix}</span>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
  
            {recommendations.longer_term.length > 0 && (
              <Section title="Longer Term">
                <ul className="flex flex-col gap-1.5">
                  {recommendations.longer_term.map((item, i) => (
                    <li key={i} className="flex gap-2 text-sm text-subtle">
                      <span className="text-indigo-400 mt-0.5 flex-shrink-0">—</span>
                      <span className="leading-relaxed">{item}</span>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
  
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium
              ${recommendations.safe_to_merge
                ? 'bg-green-400/10 text-green-400'
                : 'bg-red-400/10 text-red-400'}`}
            >
              {recommendations.safe_to_merge ? 'Safe to merge' : 'Not safe to merge'}
            </div>
          </>
        )}
      </div>
    )
  }