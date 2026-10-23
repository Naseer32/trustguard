import { createClient } from "genlayer-js";
import { testnetBradbury } from "genlayer-js/chains";
import { TransactionStatus } from "genlayer-js/types";
import { CONTRACT_ADDRESS } from "./config";
import { plain } from "./normalize";

// Read-only client: no wallet needed.
const reader = createClient({ chain: testnetBradbury });

export async function read(functionName, args = []) {
  const out = await reader.readContract({ address: CONTRACT_ADDRESS, functionName, args });
  return plain(out);
}

export function hasWallet() {
  return typeof window !== "undefined" && !!window.ethereum;
}

export async function connectWallet({ silent = false } = {}) {
  if (!hasWallet()) throw new Error("No browser wallet found. Install MetaMask and reload.");
  const accounts = await window.ethereum.request({ method: silent ? "eth_accounts" : "eth_requestAccounts" });
  if (!accounts || !accounts.length) return null;
  const address = accounts[0];
  const client = createClient({ chain: testnetBradbury, account: address });
  try {
    await client.connect("testnetBradbury");
  } catch (e) {
    // Already on the right network, or the user declined the switch; the first write reports real problems.
  }
  return { address, client };
}

// Sends a write and waits until the network has accepted it.
// onStep receives: ("wallet"), ("pending", hash), ("done", hash).
export async function write(wallet, functionName, args, onStep) {
  if (!wallet) throw new Error("Connect a wallet first.");
  onStep && onStep("wallet");
  const hash = await wallet.client.writeContract({ address: CONTRACT_ADDRESS, functionName, args, value: 0n });
  onStep && onStep("pending", hash);
  const receipt = await wallet.client.waitForTransactionReceipt({
    hash,
    status: TransactionStatus.ACCEPTED,
    retries: 200,
    interval: 3000,
  });
  onStep && onStep("done", hash);
  return { hash, receipt: plain(receipt) };
}
