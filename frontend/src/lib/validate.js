// Client-side mirror of the contract's input rules, so people see problems before paying for a transaction.
// The contract remains the authority: these checks only give early, readable feedback.

export const R_NAME = /^[A-Za-z0-9@][A-Za-z0-9._/@+-]{0,127}$/;
export const R_ECO = /^[a-z0-9][a-z0-9._-]{0,31}$/;
export const R_VER = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$/;
export const R_SHA = /^[0-9a-f]{64}$/;
export const R_REF = /^(?:https:\/\/|git\+https:\/\/|ipfs:\/\/|ar:\/\/|npm:|pypi:|cargo:|oci:|hf:)[^\s\x00-\x1f\x7f]+$/;
export const R_OBS = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?$/;
export const FLOATING = ["latest", "next", "head", "master", "main", "trunk", "stable", "nightly", "canary", "dev", "develop", "snapshot"];

export const hasCredentialsInUrl = (v) => {
  if (!/^(https:\/\/|git\+https:\/\/)/.test(v)) return false;
  const host = v.split("://")[1].split("/")[0];
  return host.includes("@");
};

export function checkDigest(v, { required = false } = {}) {
  const s = (v || "").trim().toLowerCase().replace(/^sha256:/, "");
  if (!s) return required ? "A SHA-256 digest is required." : "";
  if (!R_SHA.test(s)) return "Use exactly 64 hexadecimal characters.";
  if (/^0{64}$/.test(s)) return "An all-zero digest is not accepted.";
  return "";
}

export function checkRef(v, { required = true } = {}) {
  const s = (v || "").trim();
  if (!s) return required ? "A source reference is required." : "";
  if (s.length > 512) return "Keep the reference under 512 characters.";
  if (!R_REF.test(s)) return "Start with https://, git+https://, ipfs://, ar://, npm:, pypi:, cargo:, oci: or hf:.";
  if (hasCredentialsInUrl(s)) return "Remove credentials from the URL.";
  return "";
}

export function validateRegistration(f) {
  const e = {};
  const name = (f.name || "").trim();
  const eco = (f.ecosystem || "").trim();
  const ver = (f.version || "").trim();
  if (!name) e.name = "Enter the package, repository or model name.";
  else if (!R_NAME.test(name)) e.name = "Use letters, numbers and . _ / @ + - only, up to 128 characters.";
  if (!eco) e.ecosystem = "Enter an ecosystem such as npm or pypi.";
  else if (!R_ECO.test(eco)) e.ecosystem = "Use lowercase letters, numbers and . _ - only.";
  if (!ver) e.version = "Enter the exact version.";
  else if (!R_VER.test(ver)) e.version = "Use letters, numbers and . _ + : - only.";
  else if (FLOATING.includes(ver.toLowerCase())) e.version = "Floating versions such as latest or main are not accepted. Use an exact version.";
  const ref = checkRef(f.source_ref);
  if (ref) e.source_ref = ref;
  const dg = checkDigest(f.digest);
  if (dg) e.digest = dg;
  return e;
}

export function validateEvidence(f, today = new Date().toISOString().slice(0, 10)) {
  const e = {};
  const desc = (f.desc || "").trim();
  if (desc.length < 10) e.desc = "Describe what was found in at least 10 characters.";
  else if (desc.length > 600) e.desc = "Keep it under 600 characters.";
  const ref = checkRef(f.ref, { required: false });
  if (ref) e.ref = ref;
  const dg = checkDigest(f.digest);
  if (dg) e.digest = dg;
  const obs = (f.observed || "").trim();
  if (obs) {
    if (!R_OBS.test(obs)) e.observed = "Use a date like 2026-10-14.";
    else if (!isRealDate(obs.slice(0, 10))) e.observed = "That is not a real date.";
    else if (obs.slice(0, 10) > today) e.observed = "The date cannot be in the future.";
  }
  const refs = (f.refs || "").split(",").map((s) => s.trim()).filter(Boolean);
  if (refs.length > 8) e.refs = "At most 8 related assessments.";
  else if (refs.some((r) => !/^\d+$/.test(r))) e.refs = "Use assessment numbers separated by commas, such as 0,1.";
  return e;
}

function isRealDate(d) {
  const t = new Date(d + "T00:00:00Z");
  return !Number.isNaN(t.getTime()) && t.toISOString().slice(0, 10) === d;
}

export const hasErrors = (e) => Object.keys(e).length > 0;
