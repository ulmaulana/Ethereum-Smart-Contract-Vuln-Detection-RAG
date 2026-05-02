"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { MonacoCodeBlock } from "@/components/shared/MonacoCodeBlock";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import type { Explanation } from "@/lib/types";

export function RAGExplanation({ explanation }: { explanation: Explanation }) {
  return (
    <Card className="mt-4 border-border/60 bg-background/70 shadow-none">
      <CardContent className="space-y-5 p-5">
        <div className="flex flex-wrap items-center gap-3">
          <Badge variant="outline">{explanation.swc_id}</Badge>
          <p className="text-sm font-medium text-foreground">{explanation.title}</p>
        </div>

        <section className="rounded-3xl border border-border/60 bg-card/70 p-4">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground">
            Explanation
          </p>
          <div className="prose-rag">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code(props) {
                  const { children, className, ...rest } = props;
                  const match = /language-(\w+)/.exec(className || "");

                  if (!match) {
                    return (
                      <code className={className} {...rest}>
                        {children}
                      </code>
                    );
                  }

                  return (
                    <MonacoCodeBlock
                      language={match[1]}
                      code={String(children).replace(/\n$/, "")}
                      className="mt-4"
                    />
                  );
                },
              }}
            >
              {explanation.description_markdown}
            </ReactMarkdown>
          </div>
        </section>

        <section className="rounded-3xl border border-border/60 bg-card/70 p-4">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground">
            Mitigation
          </p>
          <div className="prose-rag">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {explanation.mitigation_markdown}
            </ReactMarkdown>
          </div>
        </section>

        <section className="rounded-3xl border border-border/60 bg-card/70 p-4">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground">
            Suggested fix snippet
          </p>
          <MonacoCodeBlock language="solidity" code={explanation.fix_code} />
        </section>
      </CardContent>
    </Card>
  );
}
