import { expect, test } from "bun:test";

test("public TypeScript source uses type aliases rather than interfaces", async () => {
  const glob = new Bun.Glob("src/**/*.ts");
  for await (const path of glob.scan("."))
    expect(await Bun.file(path).text()).not.toMatch(
      /\binterface\s+[A-Za-z_$]/u,
    );
});
