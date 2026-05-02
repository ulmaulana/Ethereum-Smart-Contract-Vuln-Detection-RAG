"use client";

import * as React from "react";
import dynamic from "next/dynamic";
import type { BeforeMount, EditorProps, OnMount } from "@monaco-editor/react";

import { useTheme } from "@/components/providers/ThemeProvider";
import {
  VS_DARK_THEME,
  VS_LIGHT_THEME,
  registerSolidityLanguage,
} from "@/lib/monaco-solidity";

const Editor = dynamic(
  async () => {
    const mod = await import("@monaco-editor/react");
    return mod.Editor as unknown as React.ComponentType<EditorProps>;
  },
  {
    ssr: false,
    loading: () => (
      <div className="h-32 animate-pulse rounded-3xl border border-border/60 bg-card/70" />
    ),
  },
);

const LINE_HEIGHT = 22;
const VERTICAL_PADDING = 16;
const MAX_HEIGHT = 600;

export function MonacoCodeBlock({
  code,
  language,
  className,
}: {
  code: string;
  language: string;
  className?: string;
}) {
  const { resolvedTheme } = useTheme();
  const initialHeight = React.useMemo(() => {
    const lines = Math.max(code.split("\n").length, 1);
    return Math.min(lines * LINE_HEIGHT + VERTICAL_PADDING, MAX_HEIGHT);
  }, [code]);
  const [height, setHeight] = React.useState<number>(initialHeight);

  const handleBeforeMount: BeforeMount = (monaco) => {
    registerSolidityLanguage(monaco);
  };

  const handleMount: OnMount = (editor) => {
    const update = () => {
      const next = Math.min(editor.getContentHeight(), MAX_HEIGHT);
      setHeight(next);
      editor.layout();
    };
    editor.onDidContentSizeChange(update);
    update();
  };

  const wrapperClass = [
    "overflow-hidden rounded-3xl border border-border/60 bg-card/70",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={wrapperClass} style={{ height }}>
      <Editor
        value={code}
        language={language}
        theme={resolvedTheme === "light" ? VS_LIGHT_THEME : VS_DARK_THEME}
        beforeMount={handleBeforeMount}
        onMount={handleMount}
        options={{
          readOnly: true,
          domReadOnly: true,
          automaticLayout: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          fontFamily:
            'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
          fontSize: 13,
          lineHeight: LINE_HEIGHT,
          padding: { top: 8, bottom: 8 },
          renderLineHighlight: "none",
          contextmenu: false,
          overviewRulerLanes: 0,
          hideCursorInOverviewRuler: true,
          glyphMargin: false,
          folding: false,
          lineNumbersMinChars: 3,
          scrollbar: { vertical: "auto", horizontal: "auto" },
        }}
      />
    </div>
  );
}
