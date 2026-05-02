"use client";

import { usePathname } from "next/navigation";

import { Footer } from "@/components/layout/Footer";
import { Header } from "@/components/layout/Header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function AppChrome({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const scanWorkspace = pathname === "/scan" || pathname === "/demo";

  if (scanWorkspace) {
    return <main>{children}</main>;
  }

  return (
    <>
      <Header />
      <main className="pb-16">
        <div className="page-shell pt-6">
          <Alert>
            <AlertTitle>Research-grade tool, not an audit replacement</AlertTitle>
            <AlertDescription>
              Hasil scan ini membantu triage awal dan edukasi mitigasi. Tetap lakukan review
              manual dan audit profesional untuk deployment production.
            </AlertDescription>
          </Alert>
        </div>
        {children}
      </main>
      <Footer />
    </>
  );
}
