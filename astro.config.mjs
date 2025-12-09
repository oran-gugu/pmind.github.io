import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://oran-gugu.github.io",
  base: "/",
  markdown: {
    syntaxHighlight: "shiki"
  }
});
