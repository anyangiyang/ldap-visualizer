const assert = require("node:assert/strict");
const core = require("../src/ldap-query-core.js");

function parseOk(source) {
  const result = core.parseFilter(source);
  assert.equal(result.ok, true, result.errors[0] && result.errors[0].message);
  return result.ast;
}

function parseFail(source, code) {
  const result = core.parseFilter(source);
  assert.equal(result.ok, false, "Expected parse failure for " + source);
  assert.equal(result.errors[0].code, code);
}

function hasRule(diagnostics, ruleId) {
  return diagnostics.some((diagnostic) => diagnostic.ruleId === ruleId);
}

const equality = parseOk("(uid=alice)");
assert.equal(equality.type, "equality");
assert.equal(equality.attribute, "uid");
assert.equal(equality.value, "alice");

const nested = parseOk("(&(objectClass=person)(|(uid=alice)(mail=alice@example.com)))");
assert.equal(nested.type, "and");
assert.equal(nested.children.length, 2);
assert.equal(nested.children[1].type, "or");

const presence = parseOk("(objectClass=*)");
assert.equal(presence.type, "presence");

const substring = parseOk("(cn=*admin*)");
assert.equal(substring.type, "substring");
assert.equal(substring.parts.any[0], "admin");

const comparison = parseOk("(loginCount>=5)");
assert.equal(comparison.type, "greater-or-equal");

const extensible = parseOk("(cn:caseExactMatch:=Alice Smith)");
assert.equal(extensible.type, "extensible");
assert.equal(extensible.matchingRule, "caseExactMatch");

const oidExtensible = parseOk("(groupType:1.2.840.113556.1.4.803:=2147483648)");
assert.equal(oidExtensible.type, "extensible");
assert.equal(oidExtensible.matchingRule, "1.2.840.113556.1.4.803");

const escaped = parseOk("(cn=Alice \\28Engineering\\29)");
assert.equal(escaped.value, "Alice (Engineering)");

parseFail("uid=alice", "expected-open-paren");
parseFail("(uid=alice", "expected-close-paren");
parseFail("(uid=Alice(", "unexpected-open-paren");
parseFail("(uid=Alice\\2)", "invalid-escape");

const broadDiagnostics = core.analyzeFilter(parseOk("(objectClass=*)"));
assert.equal(hasRule(broadDiagnostics, "broad-presence-root"), true);

const wildcardDiagnostics = core.analyzeFilter(parseOk("(&(objectClass=user)(cn=*admin*))"));
assert.equal(hasRule(wildcardDiagnostics, "contains-wildcard"), true);

const sensitiveDiagnostics = core.analyzeFilter(parseOk("(!(userPassword=*))"));
assert.equal(hasRule(sensitiveDiagnostics, "sensitive-attribute"), true);

const oidDiagnostics = core.analyzeFilter(parseOk("(groupType:1.2.840.113556.1.4.803:=2147483648)"));
assert.equal(hasRule(oidDiagnostics, "known-matching-rule"), true);

const unknownOidDiagnostics = core.analyzeFilter(parseOk("(cn:1.2.3.4.5:=alice)"));
assert.equal(hasRule(unknownOidDiagnostics, "unknown-matching-rule-oid"), true);

const duplicateDiagnostics = core.analyzeFilter(parseOk("(&(uid=alice)(uid=alice)(uid=bob))"));
assert.equal(hasRule(duplicateDiagnostics, "duplicate-condition"), true);
assert.equal(hasRule(duplicateDiagnostics, "conflicting-equality"), true);

assert.equal(core.samples.some((sample) => sample.name.startsWith("[Good]")), true);
assert.equal(core.samples.some((sample) => sample.name.startsWith("[Risky]")), true);
assert.equal(core.samples.some((sample) => sample.name.startsWith("[OID]")), true);

const mermaid = core.renderMermaid(nested, core.analyzeFilter(nested));
assert.match(mermaid, /^graph TD/);
assert.match(mermaid, /objectClass = person/);
assert.match(mermaid, /classDef normal fill:#15181e/);
assert.match(mermaid, /classDef warning fill:#ffcf25/);
assert.match(mermaid, /classDef danger fill:#e62b1e/);

console.log("All LDAP query visualizer tests passed.");
