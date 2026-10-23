// Hash routes keep deep links working on static hosting such as GitHub Pages.
export function parseHash(hash) {
  const parts = String(hash || "").replace(/^#\/?/, "").split("/").filter(Boolean);
  if (parts[0] === "registry") return { name: "registry" };
  if (parts[0] === "register") return { name: "register" };
  if (parts[0] === "artifact" && parts[1]) return { name: "artifact", id: decodeURIComponent(parts[1]), tab: parts[2] || "assessments" };
  return { name: "dashboard" };
}

export function hrefFor(route) {
  if (route.name === "registry") return "#/registry";
  if (route.name === "register") return "#/register";
  if (route.name === "artifact") return "#/artifact/" + encodeURIComponent(route.id) + (route.tab && route.tab !== "assessments" ? "/" + route.tab : "");
  return "#/";
}
