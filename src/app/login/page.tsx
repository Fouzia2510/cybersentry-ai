"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");

    try {
      const response = await fetch(
        mode === "login" ? "/api/auth/login" : "/api/auth/signup",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        },
      );
      const result = await response.json();

      if (!response.ok) {
        setError(result.error || "Authentication could not be completed.");
        return;
      }

      if (result.emailConfirmationRequired) {
        setMessage(result.message || "Check your email to confirm your account.");
        return;
      }

      router.push("/");
      router.refresh();
    } catch {
      setError("Could not reach CyberSentryAI. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card">
        <a className="auth-brand" href="/">
          <span className="auth-brand-icon">C</span>
          <span>CyberSentry<span>AI</span></span>
        </a>
        <div className="auth-eyebrow">SECURITY INTELLIGENCE PLATFORM</div>
        <h1>{mode === "login" ? "Welcome back" : "Create your workspace account"}</h1>
        <p className="auth-description">
          {mode === "login"
            ? "Sign in to manage your domains and security workspace."
            : "Create an account to start verifying domains in your workspace."}
        </p>

        <div className="auth-tabs" role="tablist" aria-label="Authentication">
          <button
            type="button"
            role="tab"
            aria-selected={mode === "login"}
            className={mode === "login" ? "selected" : ""}
            onClick={() => { setMode("login"); setError(""); setMessage(""); }}
          >
            Sign in
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "signup"}
            className={mode === "signup" ? "selected" : ""}
            onClick={() => { setMode("signup"); setError(""); setMessage(""); }}
          >
            Create account
          </button>
        </div>

        <form className="auth-form" onSubmit={submit}>
          <label htmlFor="email">Email address</label>
          <input
            id="email"
            type="email"
            autoComplete="email"
            required
            maxLength={254}
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@example.com"
          />

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            required
            minLength={8}
            maxLength={256}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="At least 8 characters"
          />

          {error && <p className="auth-error" role="alert">{error}</p>}
          {message && <p className="auth-message" role="status">{message}</p>}

          <button className="auth-submit" type="submit" disabled={busy}>
            {busy
              ? "Please wait..."
              : mode === "login"
                ? "Sign in securely"
                : "Create account"}
          </button>
        </form>

        <p className="auth-footnote">
          Your session is protected with httpOnly cookies. Domain ownership
          verification is separate from website scanning.
        </p>
        <a className="auth-back" href="/">← Back to dashboard</a>
      </section>
    </main>
  );
}
