import { it, expect } from "vitest";
import { RULE_COPY, ruleCopyFor } from "./ruleCopy";

it("maps an rce.* rule to the rce copy", () => {
  expect(ruleCopyFor("rce.untrusted_install")).toEqual(RULE_COPY.rce);
});
it("normalizes egress → exfil", () => {
  expect(ruleCopyFor("egress.post_file")).toEqual(RULE_COPY.exfil);
});
it("normalizes persistence → persist", () => {
  expect(ruleCopyFor("persistence.shell_profile")).toEqual(RULE_COPY.persist);
});
it("falls back for unknown categories", () => {
  expect(ruleCopyFor("supply.install")).toEqual({
    what: "An action that needs your review",
    risk: "Belay flagged this as potentially unsafe.",
  });
});
