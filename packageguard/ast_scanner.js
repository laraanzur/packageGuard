const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const RULES = require("./ast_rules");

const filePath = process.argv[2];
const code = fs.readFileSync(filePath, "utf8");
const lines = code.split(/\r?\n/);

function getLine(lineNumber) {
  if (!lineNumber || lineNumber < 1 || lineNumber > lines.length) {
    return "";
  }
  return lines[lineNumber - 1].trim();
}

// Add new finding to the list
function makeFinding(rule, node, extraTags = []) {
  const line = node.loc ? node.loc.start.line : null;

  return {
    rule_id: rule.rule_id,
    title: rule.title,
    severity: rule.severity,
    confidence: "",
    file: filePath,
    line,
    evidence: line ? getLine(line) : "",
    explanation_recommendation: "",
    tags: Array.from(new Set([...(rule.tags || []), ...extraTags])),
    //source: "ast"
  };
}

// Separates everything concatenated with . or [], () don't count since they carry arguments
function memberName(node) {
  if (!node) return null;

  if (node.type === "Identifier") {
    return node.name;
  }

  if (node.type === "MemberExpression") {
    const obj = memberName(node.object);
    const prop = node.property.name || node.property.value;
    return obj && prop ? `${obj}.${prop}` : null;
  }

  return null;
}

function normalizeName(name) {
  if (!name) return null;

  const parts = name.split(".");
  const first = parts[0];

  if (aliases[first]) {
    parts[0] = aliases[first];
    return parts.join(".");
  }

  return name;
}

const findings = [];
const aliases = {};
let ast;

// Try parsing from code to AST
try {
  ast = parser.parse(code, {
    sourceType: "unambiguous",
    plugins: ["jsx", "typescript"],
  });
} catch (err) {
  console.log(JSON.stringify([]));
  process.exit(0);
}

// Go through the certain node types in AST and apply functions
traverse(ast, {
  // Learn aliases for certain modules
  VariableDeclarator(path) {
    const node = path.node;
    // Looking for left side beng variable declaration and right has require + module name
    if (
      node.id.type === "Identifier" &&
      node.init &&
      node.init.type === "CallExpression" &&
      node.init.callee.name === "require" &&
      node.init.arguments[0] &&
      node.init.arguments[0].type === "StringLiteral"
    ) {
      const localName = node.id.name;
      const moduleName = node.init.arguments[0].value;

      if (["fs", "http", "https", "os", "child_process"].includes(moduleName)) {
        aliases[localName] = moduleName;
      }
    }
  },
// Function calls
  CallExpression(path) {
    // Function name
    let name = memberName(path.node.callee);
    name = normalizeName(name);

    if (RULES[name]) {

      findings.push(makeFinding(RULES[name], path.node));
    }
  },
  // When JS uses new operator
  NewExpression(path) {
    // Type of object being created
    let name = memberName(path.node.callee);
    name = normalizeName(name);

    if (RULES[name]) {
      findings.push(makeFinding(RULES[name], path.node));
    }
  },

  // Not function but an attribute/property access, like process.env
  MemberExpression(path) {
    let name = memberName(path.node);
    name = normalizeName(name);

    if (name === "process.env") {
      findings.push(makeFinding(RULES[name], path.node));
    }
  },
});


console.log(JSON.stringify(findings, null, 2));