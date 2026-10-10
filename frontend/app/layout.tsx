import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Phishing Email Detector — SOC Analysis Platform",
  description:
    "Educational defensive tool for analyzing suspicious emails and detecting phishing indicators.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-soc-bg text-soc-text min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
