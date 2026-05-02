"use client";

import * as React from "react";
import dynamic from "next/dynamic";
import type { BeforeMount, EditorProps } from "@monaco-editor/react";

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
    loading: () => <div className="min-h-[360px] flex-1" aria-hidden="true" />,
  },
);

export function SolidityEditor({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const { resolvedTheme } = useTheme();

  const handleBeforeMount: BeforeMount = (monaco) => {
    registerSolidityLanguage(monaco);
  };

  const editorBg = resolvedTheme === "light" ? "#ffffff" : "#1e1e1e";

  return (
    <div className="min-h-0 flex-1 overflow-hidden" style={{ backgroundColor: editorBg }}>
      <div className="h-full min-h-[360px] overflow-hidden" style={{ backgroundColor: editorBg }}>
        <Editor
          value={value}
          language="solidity"
          theme={resolvedTheme === "light" ? VS_LIGHT_THEME : VS_DARK_THEME}
          beforeMount={handleBeforeMount}
          onChange={(next) => onChange(next ?? "")}
          options={{
            automaticLayout: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
            fontSize: 13,
            lineHeight: 22,
            padding: { top: 16, bottom: 16 },
            tabSize: 4,
            insertSpaces: true,
            wordWrap: "off",
            renderLineHighlight: "line",
            smoothScrolling: true,
            cursorBlinking: "smooth",
            scrollbar: { vertical: "auto", horizontal: "auto" },
          }}
        />
      </div>
    </div>
  );
}
