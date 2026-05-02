"use client";

import * as React from "react";
import { FileUp, UploadCloud } from "lucide-react";
import { toast } from "sonner";

type FileUploadDropzoneProps = {
  onLoaded: (payload: { filename: string; sourceCode: string }) => void;
};

export const MAX_SOLIDITY_FILE_SIZE = 5 * 1024 * 1024;

function validateFile(file: File) {
  if (!file.name.toLowerCase().endsWith(".sol")) {
    throw new Error("Only .sol files are accepted.");
  }

  if (file.size > MAX_SOLIDITY_FILE_SIZE) {
    throw new Error("File must be 5 MB or smaller.");
  }
}

export function FileUploadDropzone({ onLoaded }: FileUploadDropzoneProps) {
  const [dragging, setDragging] = React.useState(false);

  const readFile = async (file: File) => {
    try {
      validateFile(file);
      const sourceCode = await file.text();
      onLoaded({ filename: file.name, sourceCode });
      toast.success("Contract loaded into editor");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to read file.");
    }
  };

  return (
    <label
      className={`group flex h-full min-h-[156px] cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed p-6 text-center transition ${
        dragging
          ? "border-primary bg-primary/10"
          : "border-[#d9d6ea] bg-white/55 hover:border-primary/40 hover:bg-primary/[0.04]"
      }`}
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        const file = event.dataTransfer.files?.[0];
        if (file) {
          void readFile(file);
        }
      }}
    >
      <input
        className="sr-only"
        type="file"
        accept=".sol"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) {
            void readFile(file);
          }
        }}
      />
      <div className="flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary transition-transform group-hover:scale-105">
        {dragging ? <FileUp className="size-6" /> : <UploadCloud className="size-6" />}
      </div>
      <p className="mt-5 text-base font-semibold text-[#191c1e]">
        Drop Solidity file here or browse
      </p>
      <p className="mt-2 max-w-sm text-sm text-[#6f6d7d]">
        Supports <code>.sol</code> files up to 5MB
      </p>
    </label>
  );
}
