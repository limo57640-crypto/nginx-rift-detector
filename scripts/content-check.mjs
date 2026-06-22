import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const readme = await readFile("README.md", "utf8");
const page = await readFile("docs/index.html", "utf8");

for (const text of [
  "https://ping7.cc/github-tools/",
  "https://ping7.cc/cve-repair/",
  "https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check/"
]) {
  assert(readme.includes(text), `README should include ${text}`);
  assert(page.includes(text), `GitHub Pages HTML should include ${text}`);
}

for (const text of [
  'property="og:title"',
  'property="og:description"',
  'type="application/ld+json"',
  "Issue or repair",
  "Evidence to keep",
  "No payloads. No broad scanning. No exploitation steps."
]) {
  assert(page.includes(text), `GitHub Pages HTML should include ${text}`);
}

for (const text of [
  "Issue or repair",
  "Evidence to keep",
  "No payloads. No broad scanning. No exploitation steps."
]) {
  assert(readme.includes(text), `README should include ${text}`);
}

assert(!/not only|but also|let's|comprehensive|真正|核心在于|总的来说|值得注意|不只是|而是/i.test(readme + page), "copy should avoid common AI-flavored shells");

console.log("content-check passed");
