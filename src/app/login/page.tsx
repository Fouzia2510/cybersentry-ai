"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "signup">("login");

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const requestedMode = new URLSearchParams(window.location.search).get("mode");
      if (requestedMode === "signup") setMode("signup");
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");

    if (mode === "signup" && password !== confirmPassword) {
      setError("Your passwords do not match. Please check and try again.");
      setBusy(false);
      return;
    }

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

      router.push("/dashboard");
      router.refresh();
    } catch {
      setError("Could not reach CyberSentryAI. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="auth-title">
        <Link className="auth-brand" href="/login" aria-label="CyberSentryAI login">
          <span className="auth-brand-icon">C</span>
          <span>CyberSentry<span>AI</span></span>
        </Link>
        <div className="auth-eyebrow">SECURITY INTELLIGENCE PLATFORM</div>
        <h1 id="auth-title">{mode === "login" ? "Login to your workspace" : "Create your workspace"}</h1>
        <p className="auth-description">
          {mode === "login"
            ? "Access your security operations, verified domains and assessment reports."
            : "Set up your secure workspace to manage domains and run authorized security assessments."}
        </p>

        <div className="auth-tabs" role="tablist" aria-label="Account access">
          <button type="button" role="tab" id="signin-tab" aria-controls="auth-panel"
            aria-selected={mode === "login"} className={mode === "login" ? "selected" : ""}
            onClick={() => { setMode("login"); setError(""); setMessage(""); setConfirmPassword(""); }}>
            Login
          </button>
          <button type="button" role="tab" id="signup-tab" aria-controls="auth-panel"
            aria-selected={mode === "signup"} className={mode === "signup" ? "selected" : ""}
            onClick={() => { setMode("signup"); setError(""); setMessage(""); }}>
            Create account
          </button>
        </div>

        <form className="auth-form" id="auth-panel" onSubmit={submit}>
          <div className="auth-field">
            <label htmlFor="email">Work email</label>
            <input id="email" name="email" type="email" autoComplete="email" inputMode="email"
              required maxLength={254} value={email}
              onChange={(event) => setEmail(event.target.value)} placeholder="name@company.com" />
          </div>

          <div className="auth-field">
            <div className="auth-label-row">
              <label htmlFor="password">Password</label>
              {mode === "signup" && <span className="auth-field-hint">8 characters minimum</span>}
            </div>
            <div className="auth-password-wrap">
              <input id="password" name="password" type={showPassword ? "text" : "password"}
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                required minLength={8} maxLength={256} value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder={mode === "login" ? "Enter your password" : "Create a strong password"} />
              <button className="auth-password-toggle" type="button"
                onClick={() => setShowPassword((visible) => !visible)}
                aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword}>
                {showPassword ? "Hide" : "Show"}
              </button>
            </div>
          </div>

          {mode === "signup" && (
            <div className="auth-field">
              <label htmlFor="confirm-password">Confirm password</label>
              <input id="confirm-password" name="confirmPassword"
                type={showPassword ? "text" : "password"} autoComplete="new-password"
                required minLength={8} maxLength={256} value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                placeholder="Enter your password again" />
            </div>
          )}

          {error && <p className="auth-error" role="alert">{error}</p>}
          {message && <p className="auth-message" role="status">{message}</p>}

          <button className="auth-submit" type="submit" disabled={busy}>
            {busy ? "Please wait..." : mode === "login" ? "Login to workspace" : "Create secure account"}
          </button>
        </form>

        <div className="auth-security-note">
          <span aria-hidden="true">◇</span>
          <p><strong>Secure workspace access</strong><br />
            Your session is protected with httpOnly cookies. Domain ownership is verified separately before scanning.
          </p>
        </div>
      </section>
      <p className="auth-copyright">© 2026 CyberSentryAI · Security built for defense</p>
    </main>
  );
}
