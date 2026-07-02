const fs = require("node:fs");
const path = require("node:path");

const root = process.cwd();
for (const file of ["local.settings.json", ".env", ".env.local"]) {
  if (fs.existsSync(path.join(root, file))) {
    throw new Error(`Forbidden private file present in package root: ${file}`);
  }
}

const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
if (packageJson.name !== "@plasius/oauth2-issuer") {
  throw new Error("Unexpected package name.");
}
if (packageJson.private === true) {
  throw new Error("Public package must not be marked private.");
}
console.log("public package verification passed");
