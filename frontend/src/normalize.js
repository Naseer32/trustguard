// genlayer-js may return maps and bigints. Convert to plain JS values.
export function plain(v) {
  if (v instanceof Map) {
    const o = {};
    for (const [k, val] of v.entries()) o[String(k)] = plain(val);
    return o;
  }
  if (Array.isArray(v)) return v.map(plain);
  if (typeof v === "bigint") return Number(v);
  if (v && typeof v === "object") {
    const o = {};
    for (const k of Object.keys(v)) o[k] = plain(v[k]);
    return o;
  }
  return v;
}

export function short(s, a = 8, b = 6) {
  if (!s || s.length <= a + b + 3) return s || "";
  return s.slice(0, a) + "..." + s.slice(-b);
}

export function friendlyError(e) {
  const m = String((e && (e.shortMessage || e.message)) || e);
  const code = m.match(/TG_[A-Z_]+/);
  const text = {
    TG_INPUT: "An input was rejected as invalid.",
    TG_DUPLICATE: "This item already exists.",
    TG_NOT_FOUND: "Not found.",
    TG_UNAUTHORIZED: "Only the owner can do this.",
    TG_NO_NEW_EVIDENCE: "Add new evidence before assessing again.",
    TG_LIMIT: "A limit was reached.",
    TG_PAGE: "Bad page request.",
    TG_LLM_FORMAT: "The model reply was invalid. Try again.",
  };
  return code ? `${code[0]}: ${text[code[0]] || ""} ${m.slice(0, 200)}` : m.slice(0, 300);
}

export function fmtDate(s) {
  if (!s) return "";
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export const LABEL = {
  LOW_RISK: "Low risk",
  MEDIUM_RISK: "Medium risk",
  HIGH_RISK: "High risk",
  CRITICAL_RISK: "Critical risk",
  INSUFFICIENT_EVIDENCE: "Insufficient evidence",
  UNASSESSED: "Not assessed",
};

export function ago(s) {
  const t = new Date(s).getTime();
  if (!s || Number.isNaN(t)) return s || "";
  const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 60) return "just now";
  const units = [["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [name, n] of units) {
    if (sec >= n) {
      const v = Math.floor(sec / n);
      return v + " " + name + (v === 1 ? "" : "s") + " ago";
    }
  }
  return "just now";
}

export const nice = (s) => String(s || "").replace(/_/g, " ").toLowerCase();
