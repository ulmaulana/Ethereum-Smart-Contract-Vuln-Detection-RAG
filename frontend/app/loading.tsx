import { LoadingSkeleton } from "@/components/shared/LoadingSkeleton";

export default function Loading() {
  return (
    <div className="page-shell py-10">
      <LoadingSkeleton />
    </div>
  );
}
