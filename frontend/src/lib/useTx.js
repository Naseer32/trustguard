import { useCallback, useState } from "react";
import { write } from "../chain";
import { friendlyError } from "../normalize";
import { useToast } from "./toast.jsx";

// Runs one contract write and exposes its step for a progress indicator.
// step: idle | wallet | pending | done | failed
export function useTx(wallet) {
  const [step, setStep] = useState("idle");
  const [hash, setHash] = useState("");
  const [error, setError] = useState("");
  const toast = useToast();

  const run = useCallback(async (fn, args, { success }) => {
    setError("");
    setHash("");
    try {
      const out = await write(wallet, fn, args, (s, h) => {
        setStep(s);
        if (h) setHash(h);
      });
      setStep("done");
      toast.success(success.title, success.body);
      return out;
    } catch (e) {
      const msg = friendlyError(e);
      setStep("failed");
      setError(msg);
      toast.error("The transaction did not go through", msg);
      return null;
    }
  }, [wallet, toast]);

  const reset = useCallback(() => { setStep("idle"); setHash(""); setError(""); }, []);
  return { step, hash, error, run, reset, busy: step === "wallet" || step === "pending" };
}
