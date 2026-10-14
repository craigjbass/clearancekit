// Adversarial bug-hunt pipeline: Hunter (per class) -> Skeptic (per finding) -> Referee (per survivor).
// TEMPLATE — before running via your orchestration tool:
//   1. Fill SCOPE_FILES with the resolved file list (SKILL.md Step 1).
//   2. Trim CLASSES to the ones that apply to the scope (SKILL.md Step 2 table).
//   3. Set STACK_CONTEXT to describe what the code is (language, data access, framework, front end).
//   4. Paste each class's hunt guidance from bug-classes.md into HUNT_GUIDANCE (keeps Hunters sharp).
// The pipeline skeptics and referees each class's findings as soon as that Hunter returns (no barrier).

export const meta = {
  name: 'adversarial-bug-hunt',
  description: 'Hunter (per bug-class) -> Skeptic (disprove each) -> Referee (verdict) over a fixed scope',
  phases: [
    { title: 'Hunt', detail: 'one adversarial Hunter per bug-class' },
    { title: 'Skeptic', detail: 'try to disprove each finding' },
    { title: 'Referee', detail: 'binding REAL_BUG / NOT_A_BUG / MANUAL_REVIEW verdict' },
  ],
}

// ---- ARGS NORMALISATION ----
// If the caller passes args as a JSON *string*, every field silently falls back to its default —
// including an EMPTY scope, which makes every Hunter roam the whole repo. Coerce string -> object.
const A = typeof args === 'string' ? JSON.parse(args) : (args || {})

// ---- FILL THESE IN ----
const SCOPE_FILES = A.files || [
  // 'src/orders/CreateOrderHandler.ts',
  // 'web/src/app/orders/order-form.component.ts',
]
// FAIL LOUD, never hunt nothing: an empty scope is a caller error, not a valid "scan everything".
if (!Array.isArray(SCOPE_FILES) || SCOPE_FILES.length === 0) {
  throw new Error('adversarial-bug-hunt: SCOPE_FILES is empty. Pass `args` as a JSON OBJECT (not a stringified JSON) with a non-empty `files` array from SKILL Step 1.')
}
const STACK_CONTEXT = A.stack || 'Swift. opfilter/ is an Endpoint Security system extension: every AUTH message must get exactly one respond call before its kernel deadline; shared state uses OSAllocatedUnfairLock; hand-written synchronous SQLite with signed policy rows. clearancekit/ is a SwiftUI app talking to opfilter over NSXPCConnection (Shared/XPCProtocol.swift). Shared/ is pure domain code. Full stack facts: .claude/skills/adversarial-bug-hunt/bug-classes.md'
const CLASSES = A.classes || [
  'concurrency', 'non-determinism', 'date-time', 'transaction/data',
  'perf/latency', 'error-handling', 'auth/tenant', 'async-ui', 'boundary/contract', 'resource-leak',
]
// Optional: per-class extra guidance lifted from bug-classes.md, keyed by class name.
const HUNT_GUIDANCE = A.guidance || {}
// -----------------------

const FINDINGS_SCHEMA = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['class', 'file', 'line', 'trigger', 'symptom', 'evidence', 'severity'],
        properties: {
          class: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'integer' },
          trigger: { type: 'string', description: 'EXACT sequence of operations that makes it fail' },
          symptom: { type: 'string' },
          evidence: { type: 'string' },
          severity: { enum: ['critical', 'high', 'medium', 'low'] },
        },
      },
    },
  },
}
const SKEPTIC_SCHEMA = {
  type: 'object',
  required: ['disproven', 'counter_evidence'],
  properties: {
    disproven: { type: 'boolean' },
    counter_evidence: { type: 'string' },
  },
}
const VERDICT_SCHEMA = {
  type: 'object',
  required: ['verdict', 'justification'],
  properties: {
    verdict: { enum: ['REAL_BUG', 'NOT_A_BUG', 'MANUAL_REVIEW'] },
    justification: { type: 'string' },
  },
}

const fileList = SCOPE_FILES.map(f => `- ${f}`).join('\n')

function hunterPrompt(cls) {
  const extra = HUNT_GUIDANCE[cls] ? `\nClass guidance:\n${HUNT_GUIDANCE[cls]}\n` : ''
  return `You are a bug HUNTER. Assume this code is BROKEN. Hunt ONLY for: ${cls} bugs.
Scope — read these files AND one hop of their direct callers/callees (bugs live at boundaries):
${fileList}
Stack context: ${STACK_CONTEXT}.${extra}
For EACH suspected bug provide: class, file, line, trigger (the EXACT sequence of operations
that makes it fail — e.g. "request A reads Foo L20 between request B's delete L44 and write L46"),
symptom (what production or the user observes), evidence (lines / cross-file dependency), severity.
RULES:
- No exact trigger sequence => DO NOT report it. Vague "possible issue" is noise, discard it.
- ONLY your class. Ignore style, naming, coverage, and every other bug class.
- Prefer few high-confidence findings over many guesses.
Return the findings array (empty if genuinely none).`
}

const skepticPrompt = (f) => `You are a SKEPTIC. Try to DISPROVE this bug claim. Read defensively:
find the lock, guard clause, database constraint, transaction scope, authorization registration,
single-threaded context, or framework guarantee that ALREADY makes it safe.
Claim: ${JSON.stringify(f)}
Files: ${fileList}
Set disproven=true only if you genuinely find protection; cite it in counter_evidence (file:line + why).`

const refereePrompt = (f, s) => `You are the REFEREE. Independent binding verdict. Re-read the cited code yourself.
Finding: ${JSON.stringify(f)}
Skeptic: ${JSON.stringify(s)}
Files: ${fileList}
Give verdict REAL_BUG | NOT_A_BUG | MANUAL_REVIEW + one-line justification.
MANUAL_REVIEW only when it truly cannot be judged from source alone.`

// Pipeline: each class hunts, then every finding from that class is skepticked and refereed
// concurrently — a class's findings flow to verdict without waiting on the other Hunters.
const perClass = await pipeline(
  CLASSES,
  (cls) => agent(hunterPrompt(cls), { label: `hunt:${cls}`, phase: 'Hunt', schema: FINDINGS_SCHEMA }),
  (hunt, cls) => parallel((hunt?.findings || []).map(f => () =>
    agent(skepticPrompt(f), { label: `skeptic:${f.file}:${f.line}`, phase: 'Skeptic', schema: SKEPTIC_SCHEMA })
      .then(sk => agent(refereePrompt(f, sk), { label: `referee:${f.file}:${f.line}`, phase: 'Referee', schema: VERDICT_SCHEMA })
        .then(v => ({ ...f, skeptic: sk, verdict: v.verdict, justification: v.justification })))
  ))
)

const all = perClass.flat().filter(Boolean)
const real = all.filter(f => f.verdict === 'REAL_BUG')
const manual = all.filter(f => f.verdict === 'MANUAL_REVIEW')
const killed = all.filter(f => f.verdict === 'NOT_A_BUG').length

const sevRank = { critical: 0, high: 1, medium: 2, low: 3 }
const bySeverity = (a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9)

return {
  classes_hunted: CLASSES,
  scope_file_count: SCOPE_FILES.length,
  real_bugs: real.sort(bySeverity),
  manual_review: manual.sort(bySeverity),
  false_positives_killed: killed,
}
