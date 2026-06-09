(function (root, factory) {
  var api = factory();

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }

  root.LdapQueryCore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var RFC_REFERENCES = {
    filter: {
      name: "RFC 4515",
      section: "3",
      url: "https://www.rfc-editor.org/rfc/rfc4515.html#section-3",
    },
    attributeDescription: {
      name: "RFC 4512",
      section: "2.5",
      url: "https://www.rfc-editor.org/rfc/rfc4512.html#section-2.5",
    },
  };

  var SENSITIVE_ATTRIBUTES = {
    userpassword: "LDAP password-bearing attribute",
    unicodepwd: "Active Directory password change attribute",
    memberof: "Group membership attribute",
    admincount: "Active Directory privileged account marker",
    serviceprincipalname: "Kerberos service principal attribute",
    krbprincipalname: "Kerberos principal attribute",
    ntsecuritydescriptor: "Active Directory security descriptor",
  };

  var BROAD_PRESENCE_ATTRIBUTES = {
    objectclass: true,
    cn: true,
    uid: true,
    mail: true,
    sn: true,
    givenname: true,
    ou: true,
  };

  function createParseError(code, message, offset) {
    return {
      code: code,
      message: message,
      offset: Math.max(0, offset || 0),
    };
  }

  function Parser(source) {
    this.source = source;
    this.index = 0;
    this.nextNodeId = 1;
  }

  Parser.prototype.eof = function () {
    return this.index >= this.source.length;
  };

  Parser.prototype.peek = function () {
    return this.source[this.index];
  };

  Parser.prototype.id = function () {
    var id = "n" + this.nextNodeId;
    this.nextNodeId += 1;
    return id;
  };

  Parser.prototype.skipOuterWhitespace = function () {
    while (!this.eof() && /\s/.test(this.peek())) {
      this.index += 1;
    }
  };

  Parser.prototype.expect = function (char, code, message) {
    if (this.peek() !== char) {
      throw createParseError(code, message, this.index);
    }

    this.index += 1;
  };

  Parser.prototype.parseFilter = function () {
    this.skipOuterWhitespace();
    var start = this.index;
    this.expect("(", "expected-open-paren", "Expected '(' to start an LDAP filter.");
    this.skipOuterWhitespace();

    if (this.eof()) {
      throw createParseError("unexpected-end", "Filter ended before a filter component was found.", this.index);
    }

    var node = this.parseFilterComponent(start);
    this.skipOuterWhitespace();
    this.expect(")", "expected-close-paren", "Expected ')' to close the LDAP filter.", this.index);
    node.span.start = start;
    node.span.end = this.index;
    return node;
  };

  Parser.prototype.parseFilterComponent = function (filterStart) {
    var char = this.peek();

    if (char === "&") {
      this.index += 1;
      return this.parseFilterList("and", filterStart);
    }

    if (char === "|") {
      this.index += 1;
      return this.parseFilterList("or", filterStart);
    }

    if (char === "!") {
      this.index += 1;
      this.skipOuterWhitespace();

      if (this.peek() !== "(") {
        throw createParseError("expected-open-paren", "NOT must be followed by a nested filter.", this.index);
      }

      return {
        id: this.id(),
        type: "not",
        child: this.parseFilter(),
        span: {
          start: filterStart,
          end: this.index,
        },
      };
    }

    return this.parseItem(filterStart);
  };

  Parser.prototype.parseFilterList = function (type, filterStart) {
    var children = [];

    while (!this.eof()) {
      this.skipOuterWhitespace();

      if (this.peek() !== "(") {
        break;
      }

      children.push(this.parseFilter());
    }

    if (children.length === 0) {
      throw createParseError("expected-nested-filter", type.toUpperCase() + " must contain at least one nested filter.", this.index);
    }

    return {
      id: this.id(),
      type: type,
      children: children,
      span: {
        start: filterStart,
        end: this.index,
      },
    };
  };

  Parser.prototype.parseItem = function (filterStart) {
    var itemStart = this.index;
    var itemEnd = findUnescapedCloseParen(this.source, itemStart);
    var rawItem = this.source.slice(itemStart, itemEnd);

    if (rawItem.length === 0) {
      throw createParseError("expected-attribute", "Expected an attribute description or extensible match.", itemStart);
    }

    var node = parseItemSegment(rawItem, itemStart, this.id.bind(this));
    node.span.start = filterStart;
    node.span.end = itemEnd + 1;
    this.index = itemEnd;
    return node;
  };

  function findUnescapedCloseParen(source, start) {
    var index = start;

    while (index < source.length) {
      var char = source[index];

      if (char === "\\") {
        index += 2;
        continue;
      }

      if (char === "(") {
        throw createParseError("unexpected-open-paren", "Assertion values must escape '(' as \\28.", index);
      }

      if (char === ")") {
        return index;
      }

      index += 1;
    }

    throw createParseError("expected-close-paren", "Expected ')' to close the LDAP filter.", source.length);
  }

  function parseItemSegment(rawItem, offset, nextId) {
    var extensibleIndex = rawItem.indexOf(":=");

    if (extensibleIndex !== -1) {
      return parseExtensible(rawItem, offset, extensibleIndex, nextId);
    }

    var operator = findSimpleOperator(rawItem);

    if (!operator) {
      throw createParseError("expected-operator", "Expected one of '=', '>=', '<=', '~=', or ':='.", offset);
    }

    var attribute = rawItem.slice(0, operator.index);
    var rawValue = rawItem.slice(operator.index + operator.value.length);
    var attrOffset = offset;

    validateAttribute(attribute, attrOffset);

    if (operator.value === "=") {
      return parseEqualLike(attribute, rawValue, offset + operator.index + 1, rawItem, nextId);
    }

    var decoded = decodeAssertionValue(rawValue, offset + operator.index + operator.value.length, false);

    return {
      id: nextId(),
      type: operator.value === ">=" ? "greater-or-equal" : operator.value === "<=" ? "less-or-equal" : "approx",
      attribute: attribute,
      value: decoded.value,
      rawValue: rawValue,
      hasNul: decoded.hasNul,
      span: {
        start: offset,
        end: offset + rawItem.length + 1,
      },
    };
  }

  function parseEqualLike(attribute, rawValue, valueOffset, rawItem, nextId) {
    var split = splitByUnescapedStar(rawValue, valueOffset);

    if (split.wildcardCount === 0) {
      var decoded = decodeAssertionValue(rawValue, valueOffset, false);

      return {
        id: nextId(),
        type: "equality",
        attribute: attribute,
        value: decoded.value,
        rawValue: rawValue,
        hasNul: decoded.hasNul,
        span: {
          start: valueOffset - attribute.length - 1,
          end: valueOffset + rawValue.length + 1,
        },
      };
    }

    if (rawValue === "*") {
      return {
        id: nextId(),
        type: "presence",
        attribute: attribute,
        rawValue: rawValue,
        span: {
          start: valueOffset - attribute.length - 1,
          end: valueOffset + rawValue.length + 1,
        },
      };
    }

    var parts = split.parts.map(function (part) {
      return decodeAssertionValue(part.value, part.offset, false);
    });

    return {
      id: nextId(),
      type: "substring",
      attribute: attribute,
      rawValue: rawValue,
      parts: {
        initial: rawValue[0] === "*" ? null : parts[0].value,
        any: getSubstringAnyParts(rawValue, parts),
        final: rawValue[rawValue.length - 1] === "*" ? null : parts[parts.length - 1].value,
      },
      wildcardCount: split.wildcardCount,
      hasEmptySegment: parts.some(function (part) {
        return part.value.length === 0;
      }),
      hasNul: parts.some(function (part) {
        return part.hasNul;
      }),
      span: {
        start: valueOffset - attribute.length - 1,
        end: valueOffset + rawValue.length + 1,
      },
    };
  }

  function getSubstringAnyParts(rawValue, parts) {
    return parts.slice(1, parts.length - 1).map(function (part) {
      return part.value;
    });
  }

  function parseExtensible(rawItem, offset, extensibleIndex, nextId) {
    var left = rawItem.slice(0, extensibleIndex);
    var rawValue = rawItem.slice(extensibleIndex + 2);
    var decoded = decodeAssertionValue(rawValue, offset + extensibleIndex + 2, false);
    var parsedLeft = parseExtensibleLeft(left, offset);

    return {
      id: nextId(),
      type: "extensible",
      attribute: parsedLeft.attribute,
      dnAttributes: parsedLeft.dnAttributes,
      matchingRule: parsedLeft.matchingRule,
      value: decoded.value,
      rawValue: rawValue,
      hasNul: decoded.hasNul,
      span: {
        start: offset,
        end: offset + rawItem.length + 1,
      },
    };
  }

  function parseExtensibleLeft(left, offset) {
    var attribute = null;
    var rest = left;

    if (left[0] !== ":") {
      var firstColon = left.indexOf(":");
      attribute = firstColon === -1 ? left : left.slice(0, firstColon);
      rest = firstColon === -1 ? "" : left.slice(firstColon + 1);
      validateAttribute(attribute, offset);
    } else {
      rest = left.slice(1);
    }

    var dnAttributes = false;
    var matchingRule = null;

    if (rest.length > 0) {
      var tokens = rest.split(":");

      for (var i = 0; i < tokens.length; i += 1) {
        var token = tokens[i];

        if (token.length === 0) {
          throw createParseError("invalid-extensible-match", "Extensible match contains an empty ':' segment.", offset + left.indexOf("::"));
        }

        if (token.toLowerCase() === "dn") {
          if (dnAttributes) {
            throw createParseError("invalid-extensible-match", "Extensible match repeats the 'dn' flag.", offset);
          }

          dnAttributes = true;
          continue;
        }

        if (matchingRule) {
          throw createParseError("invalid-extensible-match", "Extensible match can contain only one matching rule.", offset);
        }

        validateRuleOrOid(token, offset + left.indexOf(token));
        matchingRule = token;
      }
    }

    if (!attribute && !matchingRule) {
      throw createParseError("invalid-extensible-match", "Extensible match requires an attribute or matching rule.", offset);
    }

    return {
      attribute: attribute,
      dnAttributes: dnAttributes,
      matchingRule: matchingRule,
    };
  }

  function findSimpleOperator(rawItem) {
    var operators = [">=", "<=", "~=", "="];
    var found = null;

    for (var i = 0; i < operators.length; i += 1) {
      var operator = operators[i];
      var index = rawItem.indexOf(operator);

      if (index !== -1 && (!found || index < found.index)) {
        found = {
          value: operator,
          index: index,
        };
      }
    }

    return found;
  }

  function validateAttribute(attribute, offset) {
    if (!attribute) {
      throw createParseError("expected-attribute", "Expected an LDAP attribute description.", offset);
    }

    if (!/^(?:[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+)(?:;[A-Za-z0-9-]+)*$/.test(attribute)) {
      throw createParseError("invalid-attribute", "Invalid LDAP attribute description: " + attribute, offset);
    }
  }

  function validateRuleOrOid(value, offset) {
    if (!/^(?:[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+)$/.test(value)) {
      throw createParseError("invalid-matching-rule", "Invalid matching rule or OID: " + value, offset);
    }
  }

  function splitByUnescapedStar(rawValue, offset) {
    var parts = [];
    var current = "";
    var currentOffset = offset;
    var wildcardCount = 0;

    for (var i = 0; i < rawValue.length; i += 1) {
      var char = rawValue[i];

      if (char === "\\") {
        if (!isHex(rawValue[i + 1]) || !isHex(rawValue[i + 2])) {
          throw createParseError("invalid-escape", "LDAP escapes must use two hexadecimal digits.", offset + i);
        }

        current += rawValue.slice(i, i + 3);
        i += 2;
        continue;
      }

      if (char === "*") {
        parts.push({
          value: current,
          offset: currentOffset,
        });
        wildcardCount += 1;
        current = "";
        currentOffset = offset + i + 1;
        continue;
      }

      current += char;
    }

    parts.push({
      value: current,
      offset: currentOffset,
    });

    return {
      parts: parts,
      wildcardCount: wildcardCount,
    };
  }

  function decodeAssertionValue(rawValue, offset) {
    var output = "";
    var bytes = [];
    var hasNul = false;

    function flushBytes() {
      if (bytes.length === 0) {
        return;
      }

      if (typeof TextDecoder !== "undefined") {
        output += new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
      } else {
        output += String.fromCharCode.apply(String, bytes);
      }

      bytes = [];
    }

    for (var i = 0; i < rawValue.length; i += 1) {
      var char = rawValue[i];

      if (char === "\\") {
        if (!isHex(rawValue[i + 1]) || !isHex(rawValue[i + 2])) {
          throw createParseError("invalid-escape", "LDAP escapes must use two hexadecimal digits.", offset + i);
        }

        var byteValue = parseInt(rawValue.slice(i + 1, i + 3), 16);
        hasNul = hasNul || byteValue === 0;
        bytes.push(byteValue);
        i += 2;
        continue;
      }

      if (char === "\u0000") {
        throw createParseError("invalid-character", "NUL bytes must be escaped as \\00.", offset + i);
      }

      if (char === "(") {
        throw createParseError("invalid-character", "Assertion values must escape '(' as \\28.", offset + i);
      }

      flushBytes();
      output += char;
    }

    flushBytes();

    return {
      value: output,
      hasNul: hasNul,
    };
  }

  function isHex(value) {
    return typeof value === "string" && /^[0-9A-Fa-f]$/.test(value);
  }

  function parseFilter(source) {
    var parser = new Parser(String(source || ""));

    try {
      var ast = parser.parseFilter();
      parser.skipOuterWhitespace();

      if (!parser.eof()) {
        throw createParseError("trailing-input", "Unexpected text after the filter.", parser.index);
      }

      return {
        ok: true,
        ast: ast,
        errors: [],
      };
    } catch (error) {
      return {
        ok: false,
        ast: null,
        errors: [
          {
            code: error.code || "parse-error",
            message: error.message || String(error),
            offset: typeof error.offset === "number" ? error.offset : parser.index,
          },
        ],
      };
    }
  }

  function analyzeFilter(ast) {
    var diagnostics = [];
    var nodeById = {};
    var stats = collectStats(ast, 1, nodeById);

    addComplexityDiagnostics(diagnostics, ast, stats);
    walk(ast, function (node, parent) {
      addBroadQueryDiagnostics(diagnostics, node, parent, ast);
      addWildcardDiagnostics(diagnostics, node);
      addSensitiveAttributeDiagnostics(diagnostics, node);
      addNulDiagnostics(diagnostics, node);
      addBooleanShapeDiagnostics(diagnostics, node);
      addExtensibleDiagnostics(diagnostics, node);
    });
    addAndSiblingDiagnostics(diagnostics, ast);

    return diagnostics.map(function (diagnostic, index) {
      return Object.assign(
        {
          id: "d" + (index + 1),
        },
        diagnostic
      );
    });
  }

  function addComplexityDiagnostics(diagnostics, ast, stats) {
    if (stats.maxDepth >= 7) {
      diagnostics.push(makeDiagnostic("complexity-depth", "danger", "Very deep filter tree", "Nested filters are deep enough to be hard to review and may be expensive for directory servers.", ast));
    } else if (stats.maxDepth >= 5) {
      diagnostics.push(makeDiagnostic("complexity-depth", "warning", "Deep filter tree", "Nested filters are deep; review whether this logic can be simplified.", ast));
    }

    if (stats.totalNodes >= 25) {
      diagnostics.push(makeDiagnostic("complexity-size", "danger", "Large filter", "This filter contains many clauses and may be costly to evaluate.", ast));
    } else if (stats.totalNodes >= 12) {
      diagnostics.push(makeDiagnostic("complexity-size", "warning", "Large filter", "This filter has enough clauses to deserve a closer review.", ast));
    }
  }

  function addBroadQueryDiagnostics(diagnostics, node, parent, root) {
    if (node.type !== "presence") {
      return;
    }

    var attr = normalizeAttribute(node.attribute);
    var isRoot = node.id === root.id;

    if (isRoot && BROAD_PRESENCE_ATTRIBUTES[attr]) {
      diagnostics.push(makeDiagnostic("broad-presence-root", "danger", "Broad root presence filter", "A root-level presence filter can match a very large portion of the directory.", node));
      return;
    }

    if (attr === "objectclass") {
      diagnostics.push(makeDiagnostic("broad-objectclass-presence", isRoot ? "danger" : "warning", "Broad objectClass presence", "objectClass presence checks are commonly broad and should be paired with narrower predicates.", node));
    } else if (BROAD_PRESENCE_ATTRIBUTES[attr] && (!parent || parent.type !== "and")) {
      diagnostics.push(makeDiagnostic("broad-presence", "warning", "Potentially broad presence filter", "Presence checks on common attributes can produce broad result sets.", node));
    }
  }

  function addWildcardDiagnostics(diagnostics, node) {
    if (node.type !== "substring") {
      return;
    }

    var rawValue = node.rawValue;
    var hasLeadingWildcard = rawValue[0] === "*";
    var hasTrailingWildcard = rawValue[rawValue.length - 1] === "*";

    if (hasLeadingWildcard && hasTrailingWildcard) {
      diagnostics.push(makeDiagnostic("contains-wildcard", "warning", "Contains wildcard search", "A value wrapped in wildcards often prevents efficient indexed lookup.", node));
    } else if (hasLeadingWildcard) {
      diagnostics.push(makeDiagnostic("leading-wildcard", "warning", "Leading wildcard search", "Leading wildcards are often expensive because the prefix is unknown.", node));
    }

    if (node.wildcardCount >= 3) {
      diagnostics.push(makeDiagnostic("many-wildcards", "warning", "Many wildcard segments", "Multiple wildcard segments can make the filter harder to reason about and slower to evaluate.", node));
    }

    if (node.hasEmptySegment) {
      diagnostics.push(makeDiagnostic("empty-substring-segment", "info", "Adjacent wildcard segment", "Adjacent or edge wildcards include an empty substring segment.", node));
    }
  }

  function addSensitiveAttributeDiagnostics(diagnostics, node) {
    var attribute = getNodeAttribute(node);

    if (!attribute) {
      return;
    }

    var normalized = normalizeAttribute(attribute);
    var reason = SENSITIVE_ATTRIBUTES[normalized];

    if (!reason) {
      return;
    }

    var severity = normalized === "userpassword" || normalized === "unicodepwd" || normalized === "ntsecuritydescriptor" ? "danger" : "warning";
    diagnostics.push(makeDiagnostic("sensitive-attribute", severity, "Sensitive attribute referenced", attribute + " is a sensitive attribute. " + reason + ".", node));
  }

  function addNulDiagnostics(diagnostics, node) {
    if (!node.hasNul) {
      return;
    }

    diagnostics.push(makeDiagnostic("nul-escape", "danger", "NUL escape in assertion value", "The assertion value contains a NUL byte escape, which is worth reviewing for injection or sanitization issues.", node));
  }

  function addBooleanShapeDiagnostics(diagnostics, node) {
    if ((node.type === "and" || node.type === "or") && node.children.length === 1) {
      diagnostics.push(makeDiagnostic("single-child-boolean", "info", "Single-child boolean operator", node.type.toUpperCase() + " contains only one child and can usually be simplified.", node));
    }

    if (node.type === "or" && node.children.length >= 6) {
      diagnostics.push(makeDiagnostic("wide-or", "warning", "Wide OR branch", "Large OR branches can be costly and make query intent harder to audit.", node));
    }

    if (node.type === "not" && node.child.type === "not") {
      diagnostics.push(makeDiagnostic("double-negation", "info", "Double negation", "Nested NOT filters can usually be simplified.", node));
    }
  }

  function addExtensibleDiagnostics(diagnostics, node) {
    if (node.type !== "extensible") {
      return;
    }

    diagnostics.push(makeDiagnostic("extensible-match", "info", "Extensible match", "Extensible matches depend on server-supported matching rules and schema behavior.", node));
  }

  function addAndSiblingDiagnostics(diagnostics, ast) {
    walk(ast, function (node) {
      if (node.type !== "and") {
        return;
      }

      var seen = {};
      var equalityByAttribute = {};

      node.children.forEach(function (child) {
        var key = conditionKey(child);

        if (key) {
          if (seen[key]) {
            diagnostics.push(makeDiagnostic("duplicate-condition", "info", "Duplicate condition", "This AND branch repeats the same condition.", child));
          }

          seen[key] = true;
        }

        if (child.type === "equality") {
          var attribute = normalizeAttribute(child.attribute);
          var previous = equalityByAttribute[attribute];

          if (previous && previous.value !== child.value) {
            diagnostics.push(makeDiagnostic("conflicting-equality", "warning", "Conflicting equality checks", "This AND branch checks " + child.attribute + " against multiple values. That may be intentional for multi-valued attributes, but it deserves review.", child));
          }

          equalityByAttribute[attribute] = child;
        }
      });
    });
  }

  function conditionKey(node) {
    if (node.type === "equality") {
      return "eq:" + normalizeAttribute(node.attribute) + ":" + node.value;
    }

    if (node.type === "presence") {
      return "presence:" + normalizeAttribute(node.attribute);
    }

    if (node.type === "substring") {
      return "substring:" + normalizeAttribute(node.attribute) + ":" + node.rawValue;
    }

    return null;
  }

  function makeDiagnostic(ruleId, severity, title, message, node) {
    return {
      ruleId: ruleId,
      severity: severity,
      title: title,
      message: message,
      nodeId: node && node.id,
      span: node && node.span,
      rfc: RFC_REFERENCES.filter,
    };
  }

  function collectStats(ast, depth, nodeById) {
    var stats = {
      totalNodes: 1,
      maxDepth: depth,
    };

    nodeById[ast.id] = ast;

    childrenOf(ast).forEach(function (child) {
      var childStats = collectStats(child, depth + 1, nodeById);
      stats.totalNodes += childStats.totalNodes;
      stats.maxDepth = Math.max(stats.maxDepth, childStats.maxDepth);
    });

    return stats;
  }

  function walk(node, visitor, parent) {
    visitor(node, parent || null);
    childrenOf(node).forEach(function (child) {
      walk(child, visitor, node);
    });
  }

  function childrenOf(node) {
    if (node.type === "and" || node.type === "or") {
      return node.children;
    }

    if (node.type === "not") {
      return [node.child];
    }

    return [];
  }

  function getNodeAttribute(node) {
    return node.attribute || null;
  }

  function normalizeAttribute(attribute) {
    return String(attribute || "").toLowerCase();
  }

  function createFilterGraph(ast, diagnostics) {
    var severityByNode = {};

    diagnostics.forEach(function (diagnostic) {
      if (!diagnostic.nodeId) {
        return;
      }

      var current = severityByNode[diagnostic.nodeId];
      severityByNode[diagnostic.nodeId] = strongestSeverity(current, diagnostic.severity);
    });

    var graph = {
      nodes: [],
      edges: [],
    };

    walk(ast, function (node, parent) {
      graph.nodes.push({
        id: node.id,
        label: nodeLabel(node),
        kind: node.type,
        severity: severityByNode[node.id],
      });

      if (parent) {
        graph.edges.push({
          from: parent.id,
          to: node.id,
        });
      }
    });

    return graph;
  }

  function renderMermaid(ast, diagnostics) {
    var graph = createFilterGraph(ast, diagnostics || []);
    var lines = ["graph TD"];

    graph.nodes.forEach(function (node) {
      lines.push("  " + node.id + "[\"" + escapeMermaidLabel(node.label) + "\"]");
    });

    graph.edges.forEach(function (edge) {
      lines.push("  " + edge.from + " --> " + edge.to);
    });

    lines.push("  classDef normal fill:#15181e,stroke:#14c6cb,color:#ffffff");
    lines.push("  classDef info fill:#101a59,stroke:#2b89ff,color:#ffffff");
    lines.push("  classDef warning fill:#ffcf25,stroke:#bb5a00,color:#000000");
    lines.push("  classDef danger fill:#e62b1e,stroke:#f24c53,color:#ffffff");

    graph.nodes.forEach(function (node) {
      if (node.severity) {
        lines.push("  class " + node.id + " " + node.severity);
      } else {
        lines.push("  class " + node.id + " normal");
      }
    });

    return lines.join("\n");
  }

  function strongestSeverity(current, next) {
    var rank = {
      info: 1,
      warning: 2,
      danger: 3,
    };

    if (!current) {
      return next;
    }

    return rank[next] > rank[current] ? next : current;
  }

  function nodeLabel(node) {
    if (node.type === "and") {
      return "AND";
    }

    if (node.type === "or") {
      return "OR";
    }

    if (node.type === "not") {
      return "NOT";
    }

    if (node.type === "presence") {
      return node.attribute + " is present";
    }

    if (node.type === "substring") {
      return node.attribute + " = " + node.rawValue;
    }

    if (node.type === "equality") {
      return node.attribute + " = " + truncate(node.value, 48);
    }

    if (node.type === "greater-or-equal") {
      return node.attribute + " >= " + truncate(node.value, 48);
    }

    if (node.type === "less-or-equal") {
      return node.attribute + " <= " + truncate(node.value, 48);
    }

    if (node.type === "approx") {
      return node.attribute + " ~= " + truncate(node.value, 48);
    }

    if (node.type === "extensible") {
      var left = node.attribute || "";
      left += node.dnAttributes ? ":dn" : "";
      left += node.matchingRule ? ":" + node.matchingRule : "";
      return left + " := " + truncate(node.value, 48);
    }

    return node.type;
  }

  function escapeMermaidLabel(label) {
    return String(label).replace(/\\/g, "\\\\").replace(/"/g, "'").replace(/\n/g, " ");
  }

  function truncate(value, maxLength) {
    value = String(value);

    if (value.length <= maxLength) {
      return value;
    }

    return value.slice(0, maxLength - 1) + "...";
  }

  function summarizeDiagnostics(diagnostics) {
    return diagnostics.reduce(
      function (summary, diagnostic) {
        summary[diagnostic.severity] += 1;
        return summary;
      },
      {
        danger: 0,
        warning: 0,
        info: 0,
      }
    );
  }

  var SAMPLE_FILTERS = [
    {
      name: "AD admin lookup",
      filter: "(&(|(objectClass=user)(objectClass=person))(uid=*admin*)(memberOf=CN=Domain Admins,OU=Groups,DC=example,DC=com)(!(userPassword=*)))",
    },
    {
      name: "Narrow user lookup",
      filter: "(&(objectClass=person)(uid=alice)(mail=alice@example.com))",
    },
    {
      name: "Broad objectClass",
      filter: "(objectClass=*)",
    },
    {
      name: "Leading wildcard",
      filter: "(&(objectClass=user)(cn=*smith)(mail=*@example.com))",
    },
    {
      name: "Duplicate and conflict",
      filter: "(&(uid=alice)(uid=alice)(uid=bob))",
    },
    {
      name: "Extensible match",
      filter: "(&(objectClass=person)(cn:caseExactMatch:=Alice Smith))",
    },
    {
      name: "Escaped characters",
      filter: "(cn=Alice \\28Engineering\\29)",
    },
  ];

  return {
    parseFilter: parseFilter,
    analyzeFilter: analyzeFilter,
    createFilterGraph: createFilterGraph,
    renderMermaid: renderMermaid,
    summarizeDiagnostics: summarizeDiagnostics,
    samples: SAMPLE_FILTERS,
    references: RFC_REFERENCES,
  };
});
