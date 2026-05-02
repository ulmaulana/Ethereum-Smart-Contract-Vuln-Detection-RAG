import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const featureSources = [
  "TF-IDF lexical features from Solidity functions",
  "Hand-crafted numeric and structural indicators",
  "Signals derived from SmartBugs tool execution",
  "Expert rules capturing vulnerability-specific heuristics",
];

const techStack = [
  "Next.js 16 + React 19",
  "Tailwind CSS v3 + shadcn/ui style components",
  "TanStack Query, Zustand, React Hook Form, Zod",
  "Monaco Editor, Recharts, react-markdown",
];

export default function AboutPage() {
  return (
    <section className="page-shell py-10">
      <div className="max-w-3xl">
        <p className="text-xs uppercase tracking-[0.32em] text-primary">About</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">
          Research frontend for ML-assisted smart contract vulnerability detection.
        </h1>
        <p className="mt-4 text-lg leading-8 text-muted-foreground">
          This interface is designed for triage, experimentation, and classroom demonstration. It
          emphasizes explainability and fast review loops over production-grade assurance.
        </p>
      </div>

      <div className="mt-10 grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <Card>
          <CardHeader>
            <CardTitle>Methodology summary</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {featureSources.map((item) => (
              <div key={item} className="rounded-[22px] border border-border/60 bg-background/70 px-4 py-4">
                {item}
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Tech stack</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-3">
            {techStack.map((item) => (
              <Badge key={item} variant="outline">
                {item}
              </Badge>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Credits and limitations</CardTitle>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible>
            <AccordionItem value="limitations">
              <AccordionTrigger>Limitations disclaimer</AccordionTrigger>
              <AccordionContent>
                The model can miss exploit paths, over-report noisy patterns, or lack full semantic
                context. It should support auditors and developers, not replace them.
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="credits">
              <AccordionTrigger>Credits</AccordionTrigger>
              <AccordionContent>
                Built as an academic project for smart contract security research, combining
                machine learning, curated datasets, and retrieval-augmented explanation workflows.
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>
    </section>
  );
}
