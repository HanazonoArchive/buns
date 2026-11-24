import { useState, type FormEvent } from "react";
import { Eye, EyeOff } from "lucide-react";
import { api, type Me } from "../api";
import { Logo } from "../components/Logo";

export default function Login({ onSignedIn }: { onSignedIn: (me: Me) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onSignedIn(await api.login(email.trim(), password));
    } catch (err) {
      setError((err as Error).message);
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <section className="login-side" aria-hidden>
        <div className="login-brand">
          <Logo size={38} />
          <div>
            <span className="login-name">buns</span>
            <span className="login-tagline">Find the flaws before someone else does.</span>
          </div>
        </div>
        <div className="login-pitch">
          <p className="login-lead">Security testing for web applications, from first scan to final report.</p>
          <dl className="login-facts">
            <div><dt>Scan</dt><dd>Automated checks across your applications</dd></div>
            <div><dt>Review</dt><dd>Every finding is verified by a person</dd></div>
            <div><dt>Report</dt><dd>Clear results, ready to share</dd></div>
          </dl>
        </div>
        <p className="login-foot">Need an account? Ask your administrator.</p>
      </section>

      <main className="login-main">
        <form className="login-form" onSubmit={submit} noValidate>
          <div className="login-brand login-brand-compact">
            <Logo size={34} />
            <div>
              <span className="login-name">buns</span>
              <span className="login-tagline">Find the flaws before someone else does.</span>
            </div>
          </div>
          <h1>Sign in</h1>
          <p className="dim">Use the email and password you were given.</p>

          <label className="field">
            <span className="field-label">Email</span>
            <input type="email" autoComplete="username" autoFocus required value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="field">
            <span className="field-label">Password</span>
            <span className="pw-input">
              <input type={show ? "text" : "password"} autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
              <button type="button" className="icon-btn" onClick={() => setShow((v) => !v)} aria-label={show ? "Hide password" : "Show password"}>
                {show ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </span>
          </label>

          {error && <p className="login-error" role="alert">{error}</p>}

          <button className="btn btn-primary btn-block" disabled={busy || !email || !password}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </main>
    </div>
  );
}
