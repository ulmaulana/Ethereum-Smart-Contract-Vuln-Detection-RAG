const stats = [
  { value: "110k", label: "functions trained" },
  { value: "9", label: "SmartBugs tools integrated" },
  { value: "7", label: "vulnerability classes" },
  { value: "ID", label: "RAG explanations in Bahasa Indonesia" },
];

export function Stats() {
  return (
    <section className="page-shell py-14">
      <div className="grid gap-px overflow-hidden rounded-[32px] border border-border/60 bg-border/60 md:grid-cols-4">
        {stats.map((item) => (
          <div key={item.label} className="bg-card/80 px-6 py-8">
            <p className="text-4xl font-semibold tracking-tight text-foreground">{item.value}</p>
            <p className="mt-2 text-sm text-muted-foreground">{item.label}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
