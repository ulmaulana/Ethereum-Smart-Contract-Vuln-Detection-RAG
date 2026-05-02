"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { ScanHistoryItem, ScanRequest, ScanResponse } from "@/lib/types";

type ScanState = {
  currentScan: ScanResponse | null;
  history: ScanHistoryItem[];
  setCurrentScan: (result: ScanResponse | null) => void;
  addHistory: (request: ScanRequest, response: ScanResponse) => void;
  clearHistory: () => void;
};

export const useScanStore = create<ScanState>()(
  persist(
    (set) => ({
      currentScan: null,
      history: [],
      setCurrentScan: (result) => set({ currentScan: result }),
      addHistory: (request, response) =>
        set((state) => ({
          history: [
            {
              id: response.job_id,
              timestamp: new Date().toISOString(),
              request,
              response,
            },
            ...state.history,
          ].slice(0, 10),
        })),
      clearHistory: () => set({ history: [] }),
    }),
    {
      name: "smart-contract-vuln-detector-history",
      partialize: (state) => ({
        history: state.history,
      }),
    },
  ),
);
