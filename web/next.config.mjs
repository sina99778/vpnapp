/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Self-contained server bundle so the Docker runtime image needs no node_modules.
  output: 'standalone',
};
export default nextConfig;
