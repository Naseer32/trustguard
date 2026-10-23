import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { connectWallet, hasWallet } from "../chain";
import { friendlyError } from "../normalize";
import { useToast } from "./toast.jsx";

const Ctx = createContext(null);
export const useWallet = () => useContext(Ctx);

const FLAG = "trustguard.wallet";
const store = {
  get: () => { try { return localStorage.getItem(FLAG) === "1"; } catch { return false; } },
  set: (v) => { try { v ? localStorage.setItem(FLAG, "1") : localStorage.removeItem(FLAG); } catch { /* storage unavailable */ } },
};

export function WalletProvider({ children }) {
  const [wallet, setWallet] = useState(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const connect = useCallback(async () => {
    setBusy(true);
    try {
      const w = await connectWallet();
      if (w) {
        setWallet(w);
        store.set(true);
        toast.success("Wallet connected", w.address);
      }
    } catch (e) {
      toast.error("Could not connect the wallet", friendlyError(e));
    } finally {
      setBusy(false);
    }
  }, [toast]);

  const disconnect = useCallback(() => {
    setWallet(null);
    store.set(false);
  }, []);

  // Reconnect without a prompt if the person connected before.
  useEffect(() => {
    if (!hasWallet() || !store.get()) return;
    connectWallet({ silent: true }).then((w) => w && setWallet(w)).catch(() => {});
  }, []);

  // Follow account changes made inside the wallet.
  useEffect(() => {
    if (!hasWallet() || !window.ethereum.on) return;
    const onAccounts = (accounts) => {
      if (!accounts || !accounts.length) return disconnect();
      connectWallet({ silent: true }).then((w) => w && setWallet(w)).catch(() => {});
    };
    window.ethereum.on("accountsChanged", onAccounts);
    return () => window.ethereum.removeListener && window.ethereum.removeListener("accountsChanged", onAccounts);
  }, [disconnect]);

  return <Ctx.Provider value={{ wallet, busy, connect, disconnect, available: hasWallet() }}>{children}</Ctx.Provider>;
}
