import Link from "next/link";
import { ArrowRight, PlayCircle, Radar, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";

export function Hero() {
  return (
    <section className="relative overflow-hidden">
      <div className="absolute inset-0 -z-10 bg-radial-grid bg-grid opacity-40" />
      <div className="page-shell grid min-h-[calc(100svh-10rem)] items-center gap-12 py-14 lg:grid-cols-[1.05fr_0.95fr] lg:py-20">
        <div className="max-w-2xl">
          <p className="mb-5 text-xs uppercase tracking-[0.38em] text-primary">
            Machine Learning + RAG Security Workflow
          </p>
          <h1 className="text-5xl font-semibold tracking-tight text-balance sm:text-6xl lg:text-7xl">
            Forensic-grade scanning for Solidity contracts before they reach mainnet.
          </h1>
          <p className="mt-6 max-w-xl text-lg leading-8 text-muted-foreground">
            Paste source code, run seven vulnerability classifiers, and review mitigation guidance
            in a single operator surface tuned for smart contract triage.
          </p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <Button asChild size="lg">
              <Link href="/scan">
                Scan Your Contract
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
            <Button asChild variant="outline" size="lg">
              <Link href="/demo">
                <PlayCircle data-icon="inline-start" />
                View Demo
              </Link>
            </Button>
          </div>
        </div>

        <div className="relative">
          <div className="absolute inset-0 rounded-[36px] bg-gradient-to-br from-primary/20 via-sky-500/10 to-transparent blur-3xl" />
          <div className="panel relative overflow-hidden rounded-[36px] border-border/70 p-6">
            <div className="flex items-center justify-between border-b border-border/60 pb-4">
              <div>
                <p className="text-xs uppercase tracking-[0.32em] text-primary">Scan Console</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  Contract fingerprinting, classifier orchestration, and mitigation output.
                </p>
              </div>
              <div className="flex size-14 items-center justify-center rounded-full border border-primary/20 bg-primary/10 text-primary">
                <Radar className="size-6" />
              </div>
            </div>

            <div className="grid gap-5 py-6 sm:grid-cols-2">
              <div className="rounded-[28px] border border-border/60 bg-background/70 p-5">
                <div className="flex items-center gap-3">
                  <div className="flex size-10 items-center justify-center rounded-2xl bg-primary/10 text-primary">
                    <ShieldCheck className="size-5" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">Classifier coverage</p>
                    <p className="text-xs text-muted-foreground">SWC-linked categories</p>
                  </div>
                </div>
                <div className="mt-6 space-y-3">
                  {[
                    ["Reentrancy", "0.94"],
                    ["Access Control", "0.27"],
                    ["Denial of Service", "0.78"],
                  ].map(([label, confidence]) => (
                    <div key={label}>
                      <div className="mb-2 flex items-center justify-between text-sm">
                        <span>{label}</span>
                        <span className="text-muted-foreground">{confidence}</span>
                      </div>
                      <div className="h-2 rounded-full bg-muted">
                        <div
                          className="h-2 rounded-full bg-gradient-to-r from-primary to-sky-500"
                          style={{ width: `${Number(confidence) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-[28px] border border-border/60 bg-slate-950 p-5 font-mono text-xs text-slate-200 shadow-glow">
                <p className="text-slate-400">{"// solidity snippet"}</p>
                <pre className="mt-4 overflow-x-auto leading-6">
                  <code>{`function withdraw(uint amount) external {
  require(balance[msg.sender] >= amount);
  (bool ok,) = msg.sender.call{value: amount}("");
  require(ok);
  balance[msg.sender] -= amount;
}`}</code>
                </pre>
                <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 px-3 py-2 text-red-200">
                  Detection cue: external interaction occurs before state mutation.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
