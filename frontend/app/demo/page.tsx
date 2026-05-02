import { promises as fs } from "node:fs";
import path from "node:path";

import { ScannerWorkspaceShell } from "@/components/scan/ScannerWorkspaceShell";
import { DEMO_CONTRACTS } from "@/lib/demo-contracts";
import type { DemoContract } from "@/lib/types";

async function readDemoContracts(): Promise<DemoContract[]> {
  return Promise.all(
    DEMO_CONTRACTS.map(async (contract) => {
      const source = await fs.readFile(
        path.join(process.cwd(), "public", "demo-contracts", contract.filename),
        "utf8",
      );

      return {
        ...contract,
        source,
      };
    }),
  );
}

export default async function DemoPage() {
  const contracts = await readDemoContracts();

  return (
    <ScannerWorkspaceShell
      autoScan
      demoContracts={contracts}
      demoMode
      initialCode={contracts[0]?.source}
      initialFilename={contracts[0]?.filename}
    />
  );
}
