"use client";

import { ScannerWorkspace } from "@/components/scan/ScannerWorkspace";
import type { DemoContract } from "@/lib/types";

type ScannerWorkspaceShellProps = {
  initialCode?: string;
  initialFilename?: string;
  autoScan?: boolean;
  demoContracts?: DemoContract[];
  demoMode?: boolean;
};

export function ScannerWorkspaceShell(props: ScannerWorkspaceShellProps) {
  return <ScannerWorkspace {...props} />;
}
