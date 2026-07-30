import React, { useEffect, useState } from "react";
import { FullScreenLoader } from "@/components/Preloader";
import paths from "@/utils/paths";
import useQuery from "@/hooks/useQuery";
import System from "@/models/system";
import {
  AUTH_TIMESTAMP,
  AUTH_TOKEN,
  AUTH_USER,
  OIDC_ID_TOKEN,
} from "@/utils/constants";

/**
 * Native OIDC handoff page.
 *
 * The server-side /api/auth/oidc/callback redirects here with either a
 * single-use `token` (which we exchange for a real session token) or an
 * `error` message. Mirrors the Simple SSO passthrough page.
 */
export default function OIDCPassthrough() {
  const query = useQuery();
  const redirectPath = query.get("redirectTo") || paths.home();
  const [ready, setReady] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const callbackError = query.get("error");
    if (callbackError) {
      setError(callbackError);
      return;
    }

    try {
      if (!query.get("token")) throw new Error("No token provided.");

      // Clear any existing auth data
      window.localStorage.removeItem(AUTH_USER);
      window.localStorage.removeItem(AUTH_TOKEN);
      window.localStorage.removeItem(AUTH_TIMESTAMP);

      System.oidcExchange(query.get("token"))
        .then((res) => {
          if (!res.valid) throw new Error(res.message);

          window.localStorage.setItem(AUTH_USER, JSON.stringify(res.user));
          window.localStorage.setItem(AUTH_TOKEN, res.token);
          window.localStorage.setItem(AUTH_TIMESTAMP, Number(new Date()));
          if (res.idToken)
            window.localStorage.setItem(OIDC_ID_TOKEN, res.idToken);
          setReady(res.valid);
        })
        .catch((e) => {
          setError(e.message);
        });
    } catch (e) {
      setError(e.message);
    }
  }, []);

  if (error)
    return (
      <div className="w-screen h-screen overflow-hidden bg-theme-bg-primary flex items-center justify-center flex-col gap-4">
        <p className="text-theme-text-primary font-mono text-lg">{error}</p>
        <p className="text-theme-text-secondary font-mono text-sm">
          Please contact the system administrator about this error.
        </p>
        <a
          href={paths.login()}
          className="text-theme-text-secondary font-mono text-sm underline hover:text-sky-400"
        >
          Back to login
        </a>
      </div>
    );
  if (ready) return window.location.replace(redirectPath);

  // Loading state by default
  return <FullScreenLoader />;
}
