import Link from "next/link";

export function Footer() {
  return (
    <footer className="border-t border-border/60 bg-background/70">
      <div className="page-shell flex flex-col gap-4 py-8 text-sm text-muted-foreground md:flex-row md:items-center md:justify-between">
        <div>
          <p className="font-medium text-foreground">Powered by Smart Contract Vulnerability Detector</p>
          <p>Research project frontend for Solidity vulnerability triage and mitigation guidance.</p>
        </div>
        <div className="flex items-center gap-4">
          <Link href="/about">About</Link>
          <a href="https://github.com/your-org/your-repo" target="_blank" rel="noreferrer">
            GitHub
          </a>
        </div>
      </div>
    </footer>
  );
}
