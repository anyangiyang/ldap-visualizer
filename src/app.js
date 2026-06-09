(function () {
  "use strict";

  var core = window.LdapQueryCore;
  var elements = {};
  var currentMermaid = "";
  var currentAstJson = "";
  var mermaidRenderVersion = 0;

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    elements.sampleSelect = document.getElementById("sampleSelect");
    elements.sampleNote = document.getElementById("sampleNote");
    elements.queryInput = document.getElementById("queryInput");
    elements.analyzeButton = document.getElementById("analyzeButton");
    elements.resetButton = document.getElementById("resetButton");
    elements.parseError = document.getElementById("parseError");
    elements.diagnosticsList = document.getElementById("diagnosticsList");
    elements.nodeCount = document.getElementById("nodeCount");
    elements.dangerCount = document.getElementById("dangerCount");
    elements.warningCount = document.getElementById("warningCount");
    elements.infoCount = document.getElementById("infoCount");
    elements.graphTree = document.getElementById("graphTree");
    elements.mermaidRender = document.getElementById("mermaidRender");
    elements.mermaidFallback = document.getElementById("mermaidFallback");
    elements.toggleAstRawButton = document.getElementById("toggleAstRawButton");
    elements.copyAstButton = document.getElementById("copyAstButton");
    elements.astRawDrawer = document.getElementById("astRawDrawer");
    elements.toggleMermaidRawButton = document.getElementById("toggleMermaidRawButton");
    elements.mermaidRawDrawer = document.getElementById("mermaidRawDrawer");
    elements.copyMermaidButton = document.getElementById("copyMermaidButton");
    elements.astOutput = document.getElementById("astOutput");
    elements.mermaidOutput = document.getElementById("mermaidOutput");

    populateSamples();
    elements.queryInput.value = core.samples[0].filter;
    updateSampleNote();
    bindEvents();
    analyze();
  }

  function populateSamples() {
    core.samples.forEach(function (sample, index) {
      var option = document.createElement("option");
      option.value = String(index);
      option.textContent = sample.name;
      elements.sampleSelect.appendChild(option);
    });
  }

  function bindEvents() {
    elements.analyzeButton.addEventListener("click", analyze);
    elements.queryInput.addEventListener("input", debounce(analyze, 180));
    elements.resetButton.addEventListener("click", function () {
      var sample = core.samples[Number(elements.sampleSelect.value)];
      elements.queryInput.value = sample.filter;
      updateSampleNote();
      analyze();
    });
    elements.sampleSelect.addEventListener("change", function () {
      elements.queryInput.value = core.samples[Number(elements.sampleSelect.value)].filter;
      updateSampleNote();
      analyze();
    });
    elements.toggleAstRawButton.addEventListener("click", function () {
      toggleRawDrawer(elements.astRawDrawer, elements.toggleAstRawButton);
    });
    elements.copyAstButton.addEventListener("click", function () {
      copyText(currentAstJson);
    });
    elements.toggleMermaidRawButton.addEventListener("click", function () {
      toggleRawDrawer(elements.mermaidRawDrawer, elements.toggleMermaidRawButton);
    });
    elements.copyMermaidButton.addEventListener("click", copyMermaid);
    window.addEventListener("mermaid-ready", renderMermaidPreview);
  }

  function analyze() {
    var source = elements.queryInput.value;
    var parsed = core.parseFilter(source);

    if (!parsed.ok) {
      renderParseError(parsed.errors[0]);
      renderDiagnostics([]);
      renderGraph(null, []);
      renderRawOutputs(null, "");
      updateCounts([]);
      elements.nodeCount.textContent = "0 nodes";
      return;
    }

    var diagnostics = core.analyzeFilter(parsed.ast);
    var mermaid = core.renderMermaid(parsed.ast, diagnostics);
    currentMermaid = mermaid;
    currentAstJson = JSON.stringify(parsed.ast, null, 2);

    elements.parseError.hidden = true;
    renderDiagnostics(diagnostics);
    renderGraph(parsed.ast, diagnostics);
    renderRawOutputs(parsed.ast, mermaid);
    renderMermaidPreview();
    updateCounts(diagnostics);
    elements.nodeCount.textContent = countNodes(parsed.ast) + " nodes";
  }

  function updateSampleNote() {
    var sample = core.samples[Number(elements.sampleSelect.value)];
    elements.sampleNote.textContent = sample && sample.description ? sample.description : "";
  }

  function renderParseError(error) {
    currentMermaid = "";
    currentAstJson = "";
    elements.parseError.hidden = false;
    elements.parseError.textContent = error.message + " Offset " + error.offset + ".";
  }

  function renderDiagnostics(diagnostics) {
    elements.diagnosticsList.innerHTML = "";

    if (diagnostics.length === 0) {
      var empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "No diagnostics.";
      elements.diagnosticsList.appendChild(empty);
      return;
    }

    diagnostics.forEach(function (diagnostic) {
      var item = document.createElement("article");
      item.className = "diagnostic " + diagnostic.severity;

      var title = document.createElement("div");
      title.className = "diagnostic-title";
      title.textContent = diagnostic.title;

      var label = document.createElement("span");
      label.className = "severity-label " + diagnostic.severity;
      label.textContent = diagnostic.severity;
      title.appendChild(label);

      var message = document.createElement("div");
      message.className = "diagnostic-message";
      message.textContent = diagnostic.message;

      item.appendChild(title);
      item.appendChild(message);
      elements.diagnosticsList.appendChild(item);
    });
  }

  function renderGraph(ast, diagnostics) {
    elements.graphTree.innerHTML = "";

    if (!ast) {
      elements.mermaidRender.hidden = true;
      elements.mermaidRender.innerHTML = "";
      elements.mermaidFallback.hidden = false;
      elements.mermaidFallback.textContent = "Parse a filter to view the Mermaid graph.";
      var empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "Parse a filter to view the graph.";
      elements.graphTree.appendChild(empty);
      return;
    }

    var severityByNode = {};
    diagnostics.forEach(function (diagnostic) {
      if (diagnostic.nodeId) {
        severityByNode[diagnostic.nodeId] = strongestSeverity(severityByNode[diagnostic.nodeId], diagnostic.severity);
      }
    });

    elements.graphTree.appendChild(renderTreeNode(ast, severityByNode, true));
  }

  async function renderMermaidPreview() {
    mermaidRenderVersion += 1;
    var version = mermaidRenderVersion;

    if (!elements.mermaidRender || !currentMermaid || !window.mermaid) {
      if (elements.mermaidRender) {
        elements.mermaidRender.hidden = true;
        elements.mermaidRender.innerHTML = "";
      }
      if (elements.mermaidFallback) {
        elements.mermaidFallback.hidden = false;
        elements.mermaidFallback.textContent = currentMermaid ? "Mermaid renderer is loading. Raw source is available." : "Parse a filter to view the Mermaid graph.";
      }

      return;
    }

    try {
      if (!window.__ldapMermaidInitialized) {
        window.mermaid.initialize({
          startOnLoad: false,
          securityLevel: "strict",
          theme: "base",
          themeVariables: {
            background: "#15181e",
            mainBkg: "#15181e",
            primaryColor: "#15181e",
            primaryTextColor: "#ffffff",
            primaryBorderColor: "#14c6cb",
            lineColor: "#3b3d45",
            textColor: "#ffffff",
            fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif",
          },
        });
        window.__ldapMermaidInitialized = true;
      }

      var result = await window.mermaid.render("ldap-filter-graph-" + version, currentMermaid);

      if (version !== mermaidRenderVersion) {
        return;
      }

      elements.mermaidRender.innerHTML = result.svg;
      elements.mermaidRender.hidden = false;
      elements.mermaidFallback.hidden = true;
    } catch (error) {
      elements.mermaidRender.hidden = true;
      elements.mermaidRender.innerHTML = "";
      elements.mermaidFallback.hidden = false;
      elements.mermaidFallback.textContent = "Mermaid preview is unavailable. Raw source is available.";
      console.warn("Mermaid render failed", error);
    }
  }

  function renderTreeNode(node, severityByNode, isRoot) {
    var wrapper = document.createElement("div");
    wrapper.className = isRoot ? "tree-node root" : "tree-node";

    var chip = document.createElement("div");
    chip.className = "node-chip" + (severityByNode[node.id] ? " " + severityByNode[node.id] : "");
    chip.textContent = labelNode(node);
    wrapper.appendChild(chip);

    childrenOf(node).forEach(function (child) {
      wrapper.appendChild(renderTreeNode(child, severityByNode, false));
    });

    return wrapper;
  }

  function renderRawOutputs(ast, mermaid) {
    if (!ast) {
      elements.astOutput.textContent = "";
      elements.mermaidOutput.textContent = "";
      return;
    }

    elements.astOutput.textContent = currentAstJson;
    elements.mermaidOutput.textContent = mermaid;
  }

  function updateCounts(diagnostics) {
    var summary = core.summarizeDiagnostics(diagnostics);
    elements.dangerCount.textContent = summary.danger + " danger";
    elements.warningCount.textContent = summary.warning + " warning";
    elements.infoCount.textContent = summary.info + " info";
  }

  function copyMermaid() {
    if (!currentMermaid) {
      return;
    }

    copyText(currentMermaid);
  }

  function copyText(text) {
    if (!text) {
      return;
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
      return;
    }

    var textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }

  function toggleRawDrawer(drawer, button) {
    var willShow = drawer.hidden;
    drawer.hidden = !willShow;
    button.textContent = willShow ? "Hide Raw" : "Show Raw";
    button.setAttribute("aria-expanded", willShow ? "true" : "false");
  }

  function countNodes(node) {
    return childrenOf(node).reduce(function (total, child) {
      return total + countNodes(child);
    }, 1);
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

  function labelNode(node) {
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
      return node.attribute + " = " + node.value;
    }

    if (node.type === "greater-or-equal") {
      return node.attribute + " >= " + node.value;
    }

    if (node.type === "less-or-equal") {
      return node.attribute + " <= " + node.value;
    }

    if (node.type === "approx") {
      return node.attribute + " ~= " + node.value;
    }

    if (node.type === "extensible") {
      return (node.attribute || "") + (node.dnAttributes ? ":dn" : "") + (node.matchingRule ? ":" + node.matchingRule : "") + " := " + node.value;
    }

    return node.type;
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

  function debounce(fn, delay) {
    var timer = null;

    return function () {
      var args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () {
        fn.apply(null, args);
      }, delay);
    };
  }
})();
