import "./globals.css";

export const metadata = {
  title: "Amankan — Security Intelligence",
  description: "Attack-path & vulnerability dashboard",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
