const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const RULES = require("./ast_rules");

const filePath = process.argv[2];
const code = fs.readFileSync(filePath, "utf8");

// Add new finding to the list
function makeFinding(rule, node, extraTags = []) {

  return {
    rule_id: rule.rule_id,
    title: rule.title,
    severity: rule.severity,
    confidence: "",
    file: filePath,
    line: null,
    evidence: "",
    explanation_recommendation: "",
    tags: Array.from(new Set([rule['tags'], ...extraTags])),
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

const findings = [];
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
// Function calls
  CallExpression(path) {
    // Function name
    const name = memberName(path.node.callee);

    if (RULES[name]) {

      findings.push(makeFinding(RULES[name], path.node));
    }
  },
  // When JS uses new operator
  NewExpression(path) {
    // Type of object being created
    const name = memberName(path.node.callee);

    if (RULES[name]) {
      findings.push(makeFinding(RULES[name], path.node));
    }
  },

  // Not function but an attribute/property access, like process.env
  MemberExpression(path) {
    const name = memberName(path.node);

    if (name === "process.env") {
      findings.push(makeFinding(RULES[name], path.node));
    }
  }
});


console.log(JSON.stringify(findings, null, 2));