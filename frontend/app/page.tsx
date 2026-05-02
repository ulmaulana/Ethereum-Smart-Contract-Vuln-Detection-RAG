import { ClassesGrid } from "@/components/home/ClassesGrid";
import { Hero } from "@/components/home/Hero";
import { HowItWorks } from "@/components/home/HowItWorks";
import { Stats } from "@/components/home/Stats";

export default function HomePage() {
  return (
    <>
      <Hero />
      <Stats />
      <HowItWorks />
      <ClassesGrid />
    </>
  );
}
