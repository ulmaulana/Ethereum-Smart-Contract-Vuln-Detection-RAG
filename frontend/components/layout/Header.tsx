"use client";

import Link from "next/link";
import { ShieldAlert } from "lucide-react";
import { usePathname } from "next/navigation";

import { ThemeToggle } from "@/components/shared/ThemeToggle";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/", label: "Home" },
  { href: "/scan", label: "Scan" },
  { href: "/demo", label: "Demo" },
  { href: "/about", label: "About" },
];

export function Header() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-40 border-b border-border/60 bg-background/70 backdrop-blur-xl">
      <div className="page-shell flex h-20 items-center justify-between gap-4">
        <Link className="flex items-center gap-3" href="/">
          <div className="flex size-11 items-center justify-center rounded-2xl bg-primary/12 text-primary">
            <ShieldAlert className="size-5" />
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.32em] text-primary">JKF UAS</p>
            <p className="font-semibold">Smart Contract Vulnerability Detector</p>
          </div>
        </Link>

        <div className="flex items-center gap-2">
          <nav className="hidden items-center rounded-full border border-border/60 bg-card/70 p-1 md:flex">
            {navItems.map((item) => {
              const active = pathname === item.href;

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "rounded-full px-4 py-2 text-sm font-medium text-muted-foreground",
                    active && "bg-primary text-primary-foreground shadow-md",
                  )}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
