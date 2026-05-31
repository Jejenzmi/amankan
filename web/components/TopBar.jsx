"use client";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { useEffect, useState } from "react";
import { oidcEnabled, isAuthenticated, login, logout } from "@/lib/oidc";

export default function TopBar() {
  const path = usePathname();
  const [authed, setAuthed] = useState(false);

  // OIDC state is client-only (localStorage); resolve after mount.
  useEffect(() => {
    setAuthed(oidcEnabled() && isAuthenticated());
  }, []);

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
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ color: "var(--muted)", fontSize: 12 }}>
          Enterprise Security Intelligence Platform
        </span>
        {oidcEnabled() &&
          (authed ? (
            <button className="ghost" onClick={() => logout()}>
              Sign out
            </button>
          ) : (
            <button className="primary" onClick={() => login()}>
              Sign in
            </button>
          ))}
      </div>
    </div>
  );
}
