'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { tokenStore } from '../lib/api';

const LINKS = [
  { href: '/dashboard', label: 'Dashboard' },
  { href: '/users', label: 'Users' },
  { href: '/audit', label: 'Activity' },
];

export default function Nav() {
  const pathname = usePathname();
  const router = useRouter();

  return (
    <nav className="flex items-center gap-1 border-b border-zinc-800 bg-zinc-900/40 px-6 py-3">
      <span className="mr-4 font-semibold text-white">Secure VPN</span>
      {LINKS.map((l) => (
        <Link
          key={l.href}
          href={l.href}
          className={`rounded-md px-3 py-1.5 text-sm transition ${
            pathname === l.href ? 'bg-zinc-800 text-white' : 'text-zinc-400 hover:text-white'
          }`}
        >
          {l.label}
        </Link>
      ))}
      <button
        onClick={() => {
          tokenStore.clear();
          router.replace('/login');
        }}
        className="ml-auto rounded-md px-3 py-1.5 text-sm text-zinc-400 hover:text-white"
      >
        Sign out
      </button>
    </nav>
  );
}
