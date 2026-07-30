import { useEffect, useState } from "react";
import System from "@/models/system";

/**
 * Checks whether native OIDC (Keycloak) login is enabled so the login
 * page can render a "Login with <provider>" button. Mirrors useSimpleSSO.
 * @returns {{loading: boolean, oidcConfig: {enabled: boolean, providerName: string, disableLocalLogin: boolean}}}
 */
export default function useOidc() {
  const [loading, setLoading] = useState(true);
  const [oidcConfig, setOidcConfig] = useState({
    enabled: false,
    providerName: "SSO",
    disableLocalLogin: false,
  });

  useEffect(() => {
    async function checkOidcConfig() {
      try {
        const settings = await System.keys();
        setOidcConfig({
          enabled: settings?.OIDCEnabled ?? false,
          providerName: settings?.OIDCProviderName || "SSO",
          disableLocalLogin: settings?.OIDCDisableLocalLogin ?? false,
        });
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    checkOidcConfig();
  }, []);

  return { loading, oidcConfig };
}
