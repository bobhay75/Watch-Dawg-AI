import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Watch-Dawg KEY-9",
  description:
    "A secure action broker that lets Watch-Dawg finish contractor workflows without exposing passwords, API keys, or service identities.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
