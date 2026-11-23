import { FileLock2, UploadCloud, X } from "lucide-react";
import { useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { MAX_FILE_BYTES, validateFile } from "@/lib/security-rules";
import { cn } from "@/lib/utils";

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

export function FileUpload({
  file,
  onSelect,
  disabled,
}: {
  file: File | null;
  onSelect: (file: File | null) => void;
  disabled?: boolean;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  const handle = (next: File | null) => {
    if (!next) {
      setError(null);
      onSelect(null);
      return;
    }
    const problem = validateFile({ name: next.name, size: next.size, type: next.type });
    setError(problem);
    onSelect(problem ? null : next);
  };

  return (
    <div className="space-y-2">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          if (!disabled) handle(e.dataTransfer.files[0] ?? null);
        }}
        className={cn(
          "flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-surface/40 px-6 py-10 text-center transition-colors",
          dragging && "border-primary bg-primary/5",
          disabled && "opacity-60",
        )}
      >
        {file ? (
          <div className="flex w-full items-center gap-3 text-left">
            <FileLock2 className="size-8 text-primary" />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium">{file.name}</p>
              <p className="mono text-xs text-muted-foreground">
                {formatBytes(file.size)} · {file.type || "application/octet-stream"}
              </p>
            </div>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              disabled={disabled}
              onClick={() => handle(null)}
              aria-label="Remove selected file"
            >
              <X className="size-4" />
            </Button>
          </div>
        ) : (
          <>
            <UploadCloud className="size-8 text-muted-foreground" />
            <p className="mt-3 text-sm font-medium">Drop a confidential file here</p>
            <p className="text-xs text-muted-foreground">
              Encrypted in your browser before it leaves the device. Max{" "}
              {Math.round(MAX_FILE_BYTES / 1024 / 1024)} MB.
            </p>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="mt-4"
              disabled={disabled}
              onClick={() => inputRef.current?.click()}
            >
              Select file
            </Button>
          </>
        )}
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => handle(e.target.files?.[0] ?? null)}
        />
      </div>
      {error ? <p className="text-xs text-critical">{error}</p> : null}
    </div>
  );
}
