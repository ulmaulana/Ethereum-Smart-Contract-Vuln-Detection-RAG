import type { Metadata } from "next";
import { Inter } from "next/font/google";

import { AppChrome } from "@/components/layout/AppChrome";
import { AppProviders } from "@/components/providers/AppProviders";

import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://example.com"),
  title: "Smart Contract Vulnerability Detector",
  description:
    "ML-assisted Solidity vulnerability scanning with research-grade classifications and mitigation guidance.",
  applicationName: "Smart Contract Vulnerability Detector",
  openGraph: {
    title: "Smart Contract Vulnerability Detector",
    description:
      "Paste or upload Solidity source code and inspect vulnerability predictions with mitigation guidance.",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "Smart Contract Vulnerability Detector",
    description:
      "Research-grade vulnerability scanning for Solidity smart contracts.",
    images: ["/og-image.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning data-scroll-behavior="smooth">
      <body className={inter.variable}>
        <AppProviders>
          <div className="relative min-h-screen overflow-hidden">
            <AppChrome>{children}</AppChrome>
          </div>
        </AppProviders>
      </body>
    </html>
  );
}
