import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

// Pin the file-tracing root to this directory. Without it Next.js walks up and
// finds a stray lockfile in the home directory, inferring the wrong workspace
// root (and emitting a warning on every build/dev start).
const here = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  outputFileTracingRoot: here,
};
export default nextConfig;
