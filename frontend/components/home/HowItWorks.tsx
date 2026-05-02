const steps = [
  {
    step: "01",
    title: "Upload or paste Solidity",
    body: "Drag a .sol file into the scanner or work directly inside a Monaco editor configured for contract review.",
  },
  {
    step: "02",
    title: "Run ML classification",
    body: "Seven classifiers inspect code structure, feature vectors, tool signals, and rule-based cues to estimate risk.",
  },
  {
    step: "03",
    title: "Review mitigation guidance",
    body: "Each detected class expands into markdown explanations, code-fix suggestions, and reference links for follow-up.",
  },
];

export function HowItWorks() {
  return (
    <section className="page-shell py-14">
      <div className="mb-8 max-w-2xl">
        <p className="text-xs uppercase tracking-[0.32em] text-primary">How It Works</p>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
          One workflow from raw source to mitigation-ready context.
        </h2>
      </div>

      <div className="grid gap-px overflow-hidden rounded-[32px] border border-border/60 bg-border/60 lg:grid-cols-3">
        {steps.map((item) => (
          <article key={item.step} className="bg-card/80 p-7">
            <p className="text-xs uppercase tracking-[0.28em] text-primary">{item.step}</p>
            <h3 className="mt-6 text-xl font-semibold">{item.title}</h3>
            <p className="mt-3 leading-7 text-muted-foreground">{item.body}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
