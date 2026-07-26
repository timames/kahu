import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { login as apiLogin, setup as apiSetup, checkSetupRequired } from "@/api/client";

export function Login() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [isSetup, setIsSetup] = useState(false);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    if (isAuthenticated) { navigate("/", { replace: true }); return; }
    checkSetupRequired()
      .then((r) => setIsSetup(r.setup_required))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [isAuthenticated, navigate]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const res = isSetup
        ? await apiSetup(username, email, password)
        : await apiLogin(username, password);
      login(res.access_token, res.refresh_token, res.username, res.role);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-kahu-bg flex items-center justify-center">
        <Loader2 size={24} className="animate-spin text-kahu-accent" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-kahu-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-kahu-accent flex items-center justify-center text-white font-bold text-2xl mb-3">
            K
          </div>
          <h1 className="text-xl font-semibold text-white">
            {isSetup ? "Set Up Kahu" : "Sign In"}
          </h1>
          {isSetup && (
            <p className="text-sm text-slate-400 mt-1 text-center">
              Create the first admin account to get started.
            </p>
          )}
        </div>

        <form onSubmit={handleSubmit} className="bg-kahu-card border border-kahu-border rounded-2xl p-6 flex flex-col gap-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
              autoComplete="username"
              className="w-full bg-kahu-elevated border border-kahu-border rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-kahu-accent"
            />
          </div>

          {isSetup && (
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full bg-kahu-elevated border border-kahu-border rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-kahu-accent"
              />
            </div>
          )}

          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={isSetup ? 8 : undefined}
              autoComplete={isSetup ? "new-password" : "current-password"}
              className="w-full bg-kahu-elevated border border-kahu-border rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-kahu-accent"
            />
          </div>

          {error && (
            <div className="text-sm text-red-400 bg-red-400/10 rounded-xl px-4 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full bg-kahu-accent text-white rounded-xl px-4 py-2.5 text-sm font-medium hover:bg-blue-600 transition-colors disabled:opacity-40 flex items-center justify-center gap-2"
          >
            {submitting && <Loader2 size={14} className="animate-spin" />}
            {isSetup ? "Create Admin Account" : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
