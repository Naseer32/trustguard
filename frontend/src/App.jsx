import { useEffect, useState } from "react";
import { CONTRACT_ADDRESS } from "./config";
import { short } from "./normalize";
import { ToastProvider } from "./lib/toast.jsx";
import { WalletProvider, useWallet } from "./lib/wallet.jsx";
import { RegistryProvider } from "./lib/store.jsx";
import { useRoute } from "./lib/useRoute";
import { Icon } from "./ui/Icon.jsx";
import { CopyButton } from "./ui/bits.jsx";
import Dashboard from "./views/Dashboard.jsx";
import Registry from "./views/Registry.jsx";
import Register from "./views/Register.jsx";
import Artifact from "./views/Artifact.jsx";

function Mark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="9" className="mark-bg" />
      <rect x="6" y="19" width="4" height="7" rx="1" fill="var(--low)" />
      <rect x="12" y="15" width="4" height="11" rx="1" fill="var(--med)" />
      <rect x="18" y="10" width="4" height="16" rx="1" fill="var(--high)" />
      <rect x="24" y="6" width="4" height="20" rx="1" fill="var(--crit)" />
    </svg>
  );
}

const NAV = [
  { id: "dashboard", label: "Dashboard", href: "#/", icon: "dashboard" },
  { id: "registry", label: "Registry", href: "#/registry", icon: "registry" },
  { id: "register", label: "Register", href: "#/register", icon: "plus" },
];

function useTheme() {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem("trustguard.theme") || ""; } catch { return ""; }
  });
  useEffect(() => {
    if (theme) document.documentElement.setAttribute("data-theme", theme);
    else document.documentElement.removeAttribute("data-theme");
    try { theme ? localStorage.setItem("trustguard.theme", theme) : localStorage.removeItem("trustguard.theme"); } catch { /* storage unavailable */ }
  }, [theme]);
  const dark = theme ? theme === "dark" : window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  return { dark, toggle: () => setTheme(dark ? "light" : "dark") };
}

function WalletButton({ compact }) {
  const { wallet, busy, connect, disconnect, available } = useWallet();
  if (wallet) {
    return (
      <button className="btn wallet-on" onClick={disconnect} title="Disconnect this site from the wallet view">
        <i className="dot LOW_RISK" /> <code>{short(wallet.address, 6, 4)}</code>
      </button>
    );
  }
  return (
    <button className="btn primary" onClick={connect} disabled={busy || !available} title={available ? "" : "Open this page in a browser with a wallet such as MetaMask"}>
      <Icon name="wallet" size={16} /> {!available ? "No wallet" : busy ? "Connecting" : "Connect wallet"}
    </button>
  );
}

function Shell() {
  const route = useRoute();
  const theme = useTheme();
  const active = route.name === "artifact" ? "registry" : route.name;

  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href="#/" aria-label="TrustGuard home">
          <Mark />
          <span>TrustGuard</span>
        </a>
        <nav className="topnav" aria-label="Main">
          {NAV.map((n) => (
            <a key={n.id} href={n.href} className={active === n.id ? "on" : ""} aria-current={active === n.id ? "page" : undefined}>{n.label}</a>
          ))}
        </nav>
        <div className="topright">
          <span className="net"><i className="dot LOW_RISK" /> Bradbury testnet</span>
          <button className="icon-btn" onClick={theme.toggle} aria-label={theme.dark ? "Use light theme" : "Use dark theme"} title="Switch theme">
            <Icon name={theme.dark ? "sun" : "moon"} />
          </button>
          <WalletButton />
        </div>
      </header>

      <main className="content">
        <p className="notice">
          <Icon name="info" size={15} />
          <span>A risk signal comes from unverified evidence. It is not a guarantee of safety, and nothing is scanned or executed.</span>
        </p>
        {route.name === "dashboard" && <Dashboard />}
        {route.name === "registry" && <Registry />}
        {route.name === "register" && <Register />}
        {route.name === "artifact" && <Artifact key={route.id} id={route.id} tab={route.tab} />}
      </main>

      <footer className="footer">
        <span>Contract</span> <code>{CONTRACT_ADDRESS}</code> <CopyButton value={CONTRACT_ADDRESS} label="Copy contract address" />
        <span className="fine"> Reads show finalized state only.</span>
      </footer>

      <nav className="tabbar" aria-label="Main">
        {NAV.map((n) => (
          <a key={n.id} href={n.href} className={active === n.id ? "on" : ""} aria-current={active === n.id ? "page" : undefined}>
            <Icon name={n.icon} size={21} />
            <span>{n.label}</span>
          </a>
        ))}
      </nav>
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <WalletProvider>
        <RegistryProvider>
          <Shell />
        </RegistryProvider>
      </WalletProvider>
    </ToastProvider>
  );
}
