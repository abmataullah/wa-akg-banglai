'use client';

import { Suspense, useEffect, useRef, useState } from 'react';
import { signIn } from 'next-auth/react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Loader2 } from 'lucide-react';

function SsoLogin() {
  const searchParams = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const token = searchParams.get('token');
    if (!token) {
      setError('Missing login token.');
      return;
    }
    signIn('sso', { token, redirect: false }).then((result) => {
      if (result?.error) setError('This login link is invalid or has expired. Please try again from your dashboard.');
      else window.location.href = '/dashboard';
    });
  }, [searchParams]);

  return (
    <div className="flex items-center justify-center min-h-screen bg-background">
      <div className="text-center space-y-4 p-6">
        {error ? (
          <>
            <p className="text-destructive">{error}</p>
            <Link href="/auth/login" className="underline">Go to login</Link>
          </>
        ) : (
          <>
            <Loader2 className="h-8 w-8 animate-spin mx-auto" />
            <p className="text-muted-foreground">Signing you in...</p>
          </>
        )}
      </div>
    </div>
  );
}

export default function SsoPage() {
  return (
    <Suspense>
      <SsoLogin />
    </Suspense>
  );
}
