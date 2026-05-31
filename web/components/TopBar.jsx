"use client";
import { usePathname } from "next/navigation";
import Link from "next/link";

export default function TopBar() {
  const path = usePathname();
  return (
    <div className="topbar">
      <div className="brand">
        Aman<span>kan</span>
      </div>
      <nav>
        <Link href="/" className={path === "/" ? "active" : ""}>
          Assets &amp; Findings
        </Link>
        <Link href="/scans" className={path === "/scans" ? "active" : ""}>
          Scans
        </Link>
        <Link href="/privesc" className={path === "/privesc" ? "active" : ""}>
          Privilege Escalation
        </Link>
        <Link href="/graph" className={path === "/graph" ? "active" : ""}>
          Attack Graph
        </Link>
      </nav>
      <div style={{ marginLeft: "auto", color: "var(--muted)", fontSize: 12 }}>
        Enterprise Security Intelligence Platform
      </div>
    </div>
  );
}
