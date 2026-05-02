import { ICON_MAP, VULN_CLASS_LIST } from "@/lib/constants";

export function ClassesGrid() {
  return (
    <section className="page-shell py-14">
      <div className="mb-8 max-w-2xl">
        <p className="text-xs uppercase tracking-[0.32em] text-primary">Coverage</p>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
          Seven high-signal classes mapped to SWC categories.
        </h2>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {VULN_CLASS_LIST.map((item) => {
          const Icon = ICON_MAP[item.icon];

          return (
            <article key={item.key} className="panel p-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.28em] text-primary">{item.swc_id}</p>
                  <h3 className="mt-3 text-xl font-semibold">{item.label}</h3>
                </div>
                <div className="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary">
                  <Icon className="size-5" />
                </div>
              </div>
              <p className="mt-4 leading-7 text-muted-foreground">{item.description}</p>
            </article>
          );
        })}
      </div>
    </section>
  );
}
