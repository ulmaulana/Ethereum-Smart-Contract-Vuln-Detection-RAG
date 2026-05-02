"use client";

import * as React from "react";
import { TriangleAlert } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

type ResultsErrorBoundaryState = {
  hasError: boolean;
};

export class ResultsErrorBoundary extends React.Component<
  { children: React.ReactNode },
  ResultsErrorBoundaryState
> {
  public state: ResultsErrorBoundaryState = {
    hasError: false,
  };

  public static getDerivedStateFromError(): ResultsErrorBoundaryState {
    return { hasError: true };
  }

  public componentDidCatch(error: Error) {
    console.error("Results panel failed to render", error);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <Alert variant="destructive">
          <TriangleAlert className="size-4" />
          <AlertTitle>Results panel failed to render</AlertTitle>
          <AlertDescription>
            Try running the scan again or refresh the page. The raw response is still stored in
            local history if the request completed successfully.
          </AlertDescription>
        </Alert>
      );
    }

    return this.props.children;
  }
}
