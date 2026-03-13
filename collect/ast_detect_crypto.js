const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types'); // 引入 types 辅助判断

// --- REFAC: Common Helpers ---

// 统一的常量解析器：尝试从节点中提取字面量值
function resolveConstantFromNode(node, locLine) {
    if (!node) return null;

    // 1. Literal
    if (t.isStringLiteral(node) || t.isNumericLiteral(node) || t.isBooleanLiteral(node)) {
        return { value: node.value, line: locLine };
    }

    // 2. TemplateLiteral (no expressions)
    if (t.isTemplateLiteral(node)) {
         if (node.quasis.length === 1) {
             return { value: node.quasis[0].value.raw, line: locLine };
         }
    }
    return null;
}

// 检查是否为已知的编码包装函数
function isEncodingWrapper(callNode) {
    const callee = resolveMemberExpression(callNode.callee);
    return callee.includes('parse') && (callee.startsWith('CryptoJS.enc.') || callee.includes('Utf8') || callee.includes('Hex') || callee.includes('Base64'));
}

// --- END REFAC ---

// 统一的 resolveMemberExpression 实现
function resolveMemberExpression(node) {
    if (!node) return '';
    if (t.isIdentifier(node)) return node.name;
    if (t.isMemberExpression(node)) {
        const obj = resolveMemberExpression(node.object);
        const prop = node.property.name || (t.isStringLiteral(node.property) ? node.property.value : '');
        return obj ? obj + '.' + prop : prop;
    }
    if (t.isCallExpression(node)) {
         // Best effort for calls: foo().bar -> foo().bar (approx) or just .bar
         // For now, let's just resolve the callee
         const callee = resolveMemberExpression(node.callee);
         return callee + '()';
    }
    return '';
}

function getFunctionName(path) {
  const funcParent = path.getFunctionParent();
  if (!funcParent) return "global";
  return getFunctionNameFromNode(funcParent);
}

/**
 * Helper: Get function name from a path
 */
function getFunctionNameFromNode(path) {
  const node = path.node;
  if (node.id && node.id.name) return node.id.name;

  if (path.isFunctionExpression() || path.isArrowFunctionExpression()) {
    // Check if assigned to a variable
    if (path.parentPath.isVariableDeclarator() && path.parentPath.node.id.name) {
      return path.parentPath.node.id.name;
    }
    // Check if property of object
    if (path.parentPath.isObjectProperty() && path.parentPath.node.key.name) {
      return path.parentPath.node.key.name;
    }
    // Check if assignment (lhs = function)
    if (path.parentPath.isAssignmentExpression() && path.parentPath.node.left.property) {
        return path.parentPath.node.left.property.name || "anonymous_assigned";
    }
  }
  return "anonymous";
}

function getOutputVariable(path) {
    let parent = path.parentPath;

    // Handle chain calls e.g. encrypt().toString()
    while (parent.isMemberExpression() || parent.isCallExpression()) {
        parent = parent.parentPath;
    }

    if (parent.isVariableDeclarator()) {
        return parent.node.id.name;
    }
    if (parent.isAssignmentExpression() && parent.node.left.type === 'Identifier') {
        return parent.node.left.name;
    }
    return null;
}

function resolveFunctionPath(path, functionName) {
    const binding = path.scope.getBinding(functionName);
    if (!binding) return null;

    if (binding.path.isFunctionDeclaration()) {
        return binding.path;
    }

    if (binding.path.isVariableDeclarator()) {
        const init = binding.path.get('init');
        if (init && (init.isFunctionExpression() || init.isArrowFunctionExpression())) {
            return init;
        }
    }

    if (binding.path.isFunctionExpression() || binding.path.isArrowFunctionExpression()) {
        return binding.path;
    }

    return null;
}

function resolveObjectExpressionFromIdentifier(path, variableName) {
    const binding = path.scope.getBinding(variableName);
    if (!binding) return null;

    if (binding.path.isVariableDeclarator()) {
        const init = binding.path.get('init');
        if (!init || !init.node) return null;

        if (init.isObjectExpression()) {
            return { node: init.node, analysisPath: init };
        }

        if (init.isIdentifier()) {
            return resolveObjectExpressionFromIdentifier(init, init.node.name);
        }

        if (init.isCallExpression() && t.isIdentifier(init.node.callee)) {
            return resolveReturnedObjectExpression(init, init.node.callee.name);
        }
    }

    return null;
}

function resolveReturnedObjectExpression(path, functionName) {
    const funcPath = resolveFunctionPath(path, functionName);
    if (!funcPath) return null;

    let resolvedObject = null;
    funcPath.traverse({
        ReturnStatement(returnPath) {
            if (resolvedObject) return;
            const arg = returnPath.get('argument');
            if (!arg || !arg.node) return;

            if (arg.isObjectExpression()) {
                resolvedObject = { node: arg.node, analysisPath: returnPath };
                return;
            }

            if (arg.isIdentifier()) {
                const nested = resolveObjectExpressionFromIdentifier(returnPath, arg.node.name);
                if (nested) {
                    resolvedObject = nested;
                }
            }
        }
    });

    return resolvedObject;
}

function enrichDetailWithInputMetadata(detailTarget, basePath, argPath) {
    if (!argPath || !argPath.node) return;

    detailTarget.input_expression = generate(argPath.node).code;

    const derivation = analyzeDerivationExpression(argPath);
    if (derivation) {
        detailTarget.input_derivation = derivation;
        const sourceKeys = extractSourcesFromDerivation(derivation);
        if (sourceKeys.length > 0) {
            detailTarget.input_source_keys = sourceKeys;
        }
    }
}

function deriveFromValueNode(valueNode) {
    if (!valueNode) return null;

    // document.getElementById('username').value / querySelector(...).value
    if (t.isMemberExpression(valueNode)) {
        const propName = valueNode.property && (valueNode.property.name || (t.isStringLiteral(valueNode.property) ? valueNode.property.value : null));
        if (['value', 'checked', 'innerHTML', 'innerText'].includes(propName) && t.isCallExpression(valueNode.object)) {
            const callee = resolveMemberExpression(valueNode.object.callee);
            if (callee.includes('getElementById') || callee.includes('querySelector')) {
                const arg0 = valueNode.object.arguments && valueNode.object.arguments.length > 0 ? valueNode.object.arguments[0] : null;
                const resolved = resolveConstantFromNode(arg0, 0);
                if (resolved && resolved.value) {
                    return { type: 'source', value: resolved.value };
                }
            }
        }
    }

    // Date.now()/Math.random()/Math.floor(...)
    if (t.isCallExpression(valueNode)) {
        const callee = resolveMemberExpression(valueNode.callee);
        if (callee === 'Date.now') {
            return { type: 'identifier', name: 'timestamp' };
        }
        if (callee === 'Math.random') {
            return { type: 'identifier', name: 'random' };
        }
        if (callee === 'Math.floor' && valueNode.arguments && valueNode.arguments.length > 0) {
            const firstArg = valueNode.arguments[0];
            if (t.isBinaryExpression(firstArg) || t.isCallExpression(firstArg) || t.isMemberExpression(firstArg)) {
                const inner = deriveFromValueNode(firstArg);
                if (inner) {
                    return { type: 'op', input: inner, op: 'Math.floor', args: [] };
                }
            }
        }
    }

    // 字符串拼接
    if (t.isBinaryExpression(valueNode) && valueNode.operator === '+') {
        const left = deriveFromValueNode(valueNode.left) || (resolveConstantFromNode(valueNode.left, 0) ? { type: 'literal', value: valueNode.left.value } : null);
        const right = deriveFromValueNode(valueNode.right) || (resolveConstantFromNode(valueNode.right, 0) ? { type: 'literal', value: valueNode.right.value } : null);
        if (left || right) {
            return {
                type: 'binary_op',
                op: '+',
                left: left || { type: 'unknown' },
                right: right || { type: 'unknown' }
            };
        }
    }

    return null;
}

function buildPackingFieldSource(path, valueNode, analysisPath = path) {
    const sourceInfo = {
        source_expression: generate(valueNode).code,
        source_type: valueNode.type
    };

    if (t.isIdentifier(valueNode)) {
        sourceInfo.source_name = valueNode.name;
        const derivation = traceVariableDerivation(analysisPath, valueNode.name) || traceVariableDerivation(path, valueNode.name);
        if (derivation) {
            sourceInfo.derivation = derivation;
        }
        return sourceInfo;
    }

    const constantVal = resolveConstantFromNode(valueNode, valueNode.loc ? valueNode.loc.start.line : 0);
    if (constantVal) {
        sourceInfo.source_name = constantVal.value;
        sourceInfo.literal_value = constantVal.value;
        sourceInfo.source_type = 'literal';
        return sourceInfo;
    }

    // 先从 valueNode 本身推断（避免误用无关 NodePath）
    let directDerivation = deriveFromValueNode(valueNode);

    // 如未命中，再尝试从 analysisPath 推断（仅在两者确实同源时使用）
    if (!directDerivation && analysisPath && analysisPath.node === valueNode) {
        directDerivation = analyzeDerivationExpression(analysisPath);
    }

    // 最后兜底：在调用点 path 上尝试变量追踪
    if (!directDerivation && t.isIdentifier(valueNode)) {
        directDerivation = traceVariableDerivation(path, valueNode.name) || null;
    }

    if (directDerivation) {
        sourceInfo.derivation = directDerivation;
        const sourceKeys = extractSourcesFromDerivation(directDerivation);
        if (sourceKeys && sourceKeys.length > 0) {
            sourceInfo.source_name = sourceKeys[0];
            sourceInfo.source_keys = sourceKeys;
            return sourceInfo;
        }
    }

    // 对于复杂表达式，至少保留表达式文本作为可追踪 source_name
    if (valueNode.type === 'MemberExpression' || valueNode.type === 'CallExpression' || valueNode.type === 'BinaryExpression') {
        sourceInfo.source_name = sourceInfo.source_expression;
        return sourceInfo;
    }

    sourceInfo.source_name = sourceInfo.source_expression;
    return sourceInfo;
}

// 简单的变量值追踪器，返回 { value, line }
function resolveVariableValueWithLoc(path, variableName) {
    const binding = path.scope.getBinding(variableName);
    if (!binding) return null;

    // 查找变量定义
    if (binding.path.isVariableDeclarator()) {
        const init = binding.path.get('init');
        if (!init || !init.node) return null;
        
        const loc = binding.path.node.loc ? binding.path.node.loc.start.line : 0;

        // 1. 尝试直接解析常量
        const constantVal = resolveConstantFromNode(init.node, loc);
        if (constantVal) return constantVal;

        // 3. 常见的编码包装函数：CryptoJS.enc.Utf8.parse("...")
        if (init.isCallExpression()) {
            if (isEncodingWrapper(init.node)) {
                const args = init.get('arguments');
                if (args.length > 0) {
                    const arg0 = args[0];
                    // 递归解析参数值
                    const argConst = resolveConstantFromNode(arg0.node, loc);
                    if (argConst) return argConst;

                    if (arg0.isIdentifier()) {
                        return resolveVariableValueWithLoc(path, arg0.node.name);
                    }
                }
            }
        }
    }
    return null;
}

// 兼容旧接口
function resolveVariableValue(path, variableName) {
    const res = resolveVariableValueWithLoc(path, variableName);
    return res ? res.value : null;
}

// 查找变量定义的初始节点 (Node)
function resolveVariableInitNode(path, variableName) {
    const binding = path.scope.getBinding(variableName);
    if (!binding) return null;
    if (binding.path.isVariableDeclarator()) {
        const init = binding.path.get('init');
        // Ensure that init.node exists before accessing
        if (init && init.node) {
            return { node: init.node, path: init, line: binding.path.node.loc ? binding.path.node.loc.start.line : 0 };
        }
    }
    return null;
}

/**
 * 尝试追踪变量的衍生逻辑 (Derivation Logic)
 * 返回结构: { type: "dependency", source: "payload_key", operations: [...] }
 */
function traceVariableDerivation(path, variableName) {
    const binding = path.scope.getBinding(variableName);
    if (!binding) return null;

    if (binding.path.isVariableDeclarator()) {
        const init = binding.path.get('init');
        if (init && init.node) {
             return analyzeDerivationExpression(init);
        }
    }

    if (binding.constantViolations && binding.constantViolations.length > 0) {
        for (let i = binding.constantViolations.length - 1; i >= 0; i--) {
            const violation = binding.constantViolations[i];
            if (violation.isAssignmentExpression()) {
                const right = violation.get('right');
                if (right && right.node) {
                    const derived = analyzeDerivationExpression(right);
                    if (derived) return derived;
                }
            }
        }
    }
    return null;
}

function extractArgumentValue(arg, path) {
    // 支持字面量、标识符、对象、数组、函数调用等
    if (t.isLiteral(arg)) {
        return arg.value;
    } else if (t.isIdentifier(arg)) {
        // 1. 尝试直接获取字面量值
        const res = resolveVariableValueWithLoc(path, arg.name);
        if (res) return res.value;
        // 2. 追踪衍生链
        const derivation = traceVariableDerivation(path, arg.name);
        if (derivation) return derivation;
        
        return { type: 'identifier', name: arg.name };
    } else if (t.isObjectExpression(arg)) {
        // 提取对象属性
        const obj = {};
        arg.properties.forEach(p => {
            if (t.isObjectProperty(p)) {
                const key = p.key.name || p.key.value;
                obj[key] = extractArgumentValue(p.value, path);
            }
        });
        return obj;
    } else if (t.isArrayExpression(arg)) {
        return arg.elements.map(e => extractArgumentValue(e, path));
    } else if (t.isCallExpression(arg)) {
        // 递归解析函数调用
        const callee = resolveMemberExpression(arg.callee);
        const args = arg.arguments.map(a => extractArgumentValue(a, path));
        return { type: 'call', callee, args };
    } else if (t.isMemberExpression(arg)) {
        return resolveMemberExpression(arg);
    }
    return '?';
}

function analyzeDerivationExpression(path) {
    if (!path || !path.node) return null;

    // 0. 字面量直接返回
    const constantVal = resolveConstantFromNode(path.node, path.node.loc ? path.node.loc.start.line : 0);
    if (constantVal) return { type: "literal", value: constantVal.value };

    // 1. 追踪输入源 (document.getElementById(...).value)
    if (path.isMemberExpression()) {
        const propName = path.node.property.name || (t.isStringLiteral(path.node.property) ? path.node.property.value : null);
        
        if (['value', 'checked', 'innerHTML', 'innerText'].includes(propName)) {
            const object = path.get('object');
            if (object.isCallExpression()) {
                const callee = resolveMemberExpression(object.get('callee').node);
                if (callee.includes('getElementById') || callee.includes('querySelector') || callee.includes('jquery') || callee.startsWith('$')) {
                    const args = object.get('arguments');
                    // 提取第一个 ID 参数
                    const arg0 = args.length > 0 ? resolveConstantFromNode(args[0].node, 0) : null;
                    if (arg0) {
                        return { type: "source", value: arg0.value };
                    }
                }
            }
            // Handle: var el = document.getElementById('x'); el.value;
            if (object.isIdentifier()) {
                 // 这里暂不深入追踪 DOM 元素引用，只是预留
            }
        }

        const parentDerivation = analyzeDerivationExpression(path.get('object'));
        if (parentDerivation && propName) {
            return { type: "member_access", input: parentDerivation, property: propName };
        }
    }

    // 2. 追踪变量引用
    if (path.isIdentifier()) {
        const binding = path.scope.getBinding(path.node.name);
        if (binding && binding.path.isVariableDeclarator()) {
            const init = binding.path.get('init');
            return analyzeDerivationExpression(init);
        }
    }

    // 3. 链式调用 (.slice(...).padEnd(...))
    if (path.isCallExpression()) {
        const callee = path.get('callee');
        const fullCall = resolveMemberExpression(callee.node);

        if (fullCall === 'JSON.stringify') {
            const arg0 = path.get('arguments.0');
            if (arg0 && arg0.node) {
                const inner = analyzeDerivationExpression(arg0);
                return {
                    type: 'op',
                    input: inner || { type: 'identifier', name: generate(arg0.node).code },
                    op: 'JSON.stringify',
                    args: []
                };
            }
        }

        if (callee.isMemberExpression()) {
            const method = callee.node.property.name;
            const object = callee.get('object');

            // 特殊处理 CryptoJS 包装函数
            if (fullCall.includes('parse') && (fullCall.includes('Utf8') || fullCall.includes('Hex') || fullCall.includes('Base64'))) {
                 const arg0 = path.get('arguments.0');
                 if (arg0 && arg0.node) {
                     const inner = analyzeDerivationExpression(arg0);
                     const cleanOp = fullCall.split('.').slice(-2).join('.');
                     if (inner) {
                         return { type: "op", input: inner, op: cleanOp, args: [] };
                     }
                     return { type: "op", input: analyzeDerivationExpression(arg0), op: cleanOp, args: [] };
                 }
            }

            const parentDerivation = analyzeDerivationExpression(object);

            if (parentDerivation) {
                const args = path.get('arguments').map(argPath => {
                    const derivation = analyzeDerivationExpression(argPath);
                    if (derivation) return derivation;
                    return extractArgumentValue(argPath.node, path);
                });

                return { type: "op", input: parentDerivation, op: method, args: args };
            }
        }

        const analyzedArgs = path.get('arguments').map(argPath => {
            const derivation = analyzeDerivationExpression(argPath);
            if (derivation) return derivation;
            return extractArgumentValue(argPath.node, path);
        });

        return {
            type: 'call',
            callee: fullCall || generate(path.node.callee).code,
            args: analyzedArgs,
            expression: generate(path.node).code
        };
    }

    // 4. 二元运算 ("str" + var)
    if (path.isBinaryExpression() && path.node.operator === '+') {
        const left = analyzeDerivationExpression(path.get('left'));
        const right = analyzeDerivationExpression(path.get('right'));

        // 只要有一边是衍生链/变量，就构建二元操作节点
        if (left || right) {
             // 包装字面量或占位符
             const leftOp = left ? left : (resolveConstantFromNode(path.node.left, 0) ? { type: "literal", value: path.node.left.value } : { type: "unknown" });
             const rightOp = right ? right : (resolveConstantFromNode(path.node.right, 0) ? { type: "literal", value: path.node.right.value } : { type: "unknown" });

             return { type: "binary_op", op: "+", left: leftOp, right: rightOp };
        }
    }

    return null;
}

// 获取变量定义的行号
function resolveVariableLine(path, variableName) {
    const binding = path.scope.getBinding(variableName);
    if (binding && binding.path.node.loc) {
        return binding.path.node.loc.start.line;
    }
    return 0;
}

// 递归从 Derivation 结构中提取所有 source value
function extractSourcesFromDerivation(derivation) {
    if (!derivation) return [];

    if (derivation.type === 'source') {
        return [derivation.value];
    }

    let sources = [];

    if (derivation.input) {
         sources = sources.concat(extractSourcesFromDerivation(derivation.input));
    }

    if (derivation.left) {
         sources = sources.concat(extractSourcesFromDerivation(derivation.left));
    }

    if (derivation.right) {
         sources = sources.concat(extractSourcesFromDerivation(derivation.right));
    }

    if (derivation.args && Array.isArray(derivation.args)) {
        derivation.args.forEach(arg => {
             if (arg && typeof arg === 'object') {
                  sources = sources.concat(extractSourcesFromDerivation(arg));
             }
        });
    }

    return [...new Set(sources)]; // 去重
}

// 尝试推断 Payload 结构
function inferPayloadStructure(path, variableName) {
    const binding = path.scope.getBinding(variableName);
    if (!binding) return null;

    // 直接追踪定义：const jsonData = JSON.stringify(formData);
    if (binding.path.isVariableDeclarator()) {
        const init = binding.path.get('init');
        // Case A: JSON.stringify(obj)
        if (init.isCallExpression() &&
            init.get('callee').matchesPattern('JSON.stringify')) {
            const arg0 = init.get('arguments.0');
            if (arg0 && arg0.isIdentifier()) {
                // 递归追踪 JSON.stringify 的参数
                return inferPayloadStructure(arg0, arg0.node.name);
            } else if (arg0 && arg0.isObjectExpression()) {
                 return extractObjectKeys(arg0);
            }
        }
        // Case B: 直接的对象字面量 const data = { u: 1, p: 2 }
        if (init.isObjectExpression()) {
            return extractObjectKeys(init);
        }

        // Case C: Single DOM value via analyzeDerivationExpression
        const derivation = analyzeDerivationExpression(init);
        if (derivation) {
             const sources = extractSourcesFromDerivation(derivation);
             if (sources.length > 0) {
                 return sources;
             }
        }
    }
    // 新增：AssignmentExpression 追踪
    if (binding.path.isAssignmentExpression()) {
        // 只追踪简单的 a = b 赋值
        const right = binding.path.get('right');

        // Check for DOM usage
        const derivation = analyzeDerivationExpression(right);
        if (derivation) {
             const sources = extractSourcesFromDerivation(derivation);
             if (sources.length > 0) {
                 return sources;
             }
        }

        if (right.isIdentifier()) {
            return inferPayloadStructure(right, right.node.name);
        } else if (right.isObjectExpression()) {
            return extractObjectKeys(right);
        } else if (right.isCallExpression() && right.get('callee').matchesPattern('JSON.stringify')) {
            const arg0 = right.get('arguments.0');
            if (arg0 && arg0.isIdentifier()) {
                return inferPayloadStructure(arg0, arg0.node.name);
            } else if (arg0 && arg0.isObjectExpression()) {
                return extractObjectKeys(arg0);
            }
        }
    }
    return null;
}

function extractObjectKeys(objectExpressionPath) {
    const keys = [];
    objectExpressionPath.get('properties').forEach(prop => {
        if (prop.isObjectProperty()) {
            const key = prop.get('key');
            if (key.isIdentifier()) {
                keys.push(key.node.name);
            } else if (key.isStringLiteral()) {
                keys.push(key.node.value);
            }
        }
    });
    return keys.length > 0 ? keys : null;
}

// Configure CLI
const { program } = require('commander');

program
  .option('-i, --input <file>', 'Input JS file to analyze')
  .option('-o, --output <file>', 'Output JSON file for results')
  .parse(process.argv);

const options = program.opts();

if (!options.input) {
  console.error("Error: Input file required (-i)");
  process.exit(1);
}

const sourceCode = fs.readFileSync(options.input, 'utf-8');

// Parse AST
let ast;
try {
  // First attempt: Script mode with allowance
  ast = parser.parse(sourceCode, {
    sourceType: 'script',
    allowReturnOutsideFunction: true,
    plugins: ['jsx', 'typescript', 'classProperties']
  });
} catch (e) {
  // Second attempt: Unambiguous (might fail on return, so we catch)
  try {
    ast = parser.parse(sourceCode, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      plugins: ['jsx', 'typescript', 'classProperties']
    });
  } catch (e2) {
      // Third attempt: Wrap in function (catch-all for fragmentation)
      try {
          ast = parser.parse("(function(){\n" + sourceCode + "\n})", {
            sourceType: 'script',
            plugins: ['jsx', 'typescript', 'classProperties']
          });
      } catch (e3) {
          console.error("Failed to parse JavaScript:", e3.message);
          // Return empty structure instead of crashing
          console.log(JSON.stringify({ file: options.input, findings: [], functions: [], error: e3.message }));
          process.exit(0);
      }
  }
}

const findings = [];
const functions = []; // New: Collect Function Info


/**
 * Helper: Resolve MemberExpression to string (e.g. CryptoJS.AES.encrypt)
 */
// 删除顶部 resolveMemberExpression 声明，保留406行后的唯一实现

// 提取 HTTP Body 构造逻辑
function detectPayloadPacking(path, contextName) {
    const args = path.node.arguments;
    if (args.length < 2) return null;

    let bodyNode = null;

    // 1. fetch(url, { body: ... })
    if (contextName === 'fetch' && args[1].type === 'ObjectExpression') {
        const bodyProp = args[1].properties.find(p => p.key && p.key.name === 'body');
        if (bodyProp) bodyNode = bodyProp.value;
    }
    // 2. axios.post(url, data, ...)
    else if (contextName.startsWith('axios') && args.length >= 2) {
        bodyNode = args[1];
    }

    if (!bodyNode) return null;

    // Resolve Identifier to its definition
    if (bodyNode.type === 'Identifier') {
        const resolved = resolveVariableInitNode(path, bodyNode.name);
        if (resolved && resolved.node) {
             bodyNode = resolved.node;
        }
    }

    const packing = [];

    // Case A: Template Literal `key=${val}&...`
    if (bodyNode.type === 'TemplateLiteral') {
        let pattern = "";
        const fieldSources = {};
        bodyNode.quasis.forEach((q, i) => {
            pattern += q.value.raw;
            if (i < bodyNode.expressions.length) {
                const expr = bodyNode.expressions[i];
                let varName = "unknown";
                if (expr.type === 'CallExpression' && expr.callee.name === 'encodeURIComponent') {
                     if (expr.arguments[0].type === 'Identifier') varName = expr.arguments[0].name;
                } else if (expr.type === 'Identifier') {
                     varName = expr.name;
                }
                pattern += `{{${varName}}}`;
                packing.push({ type: "template_insertion", position: i, variable: varName });
                fieldSources[varName] = { source_name: varName, source_expression: generate(expr).code, source_type: expr.type };
            }
        });
        return { type: "template", template: pattern, insertions: packing, field_sources: fieldSources };
    }
    // Case B: JSON.stringify({...})
    else if (bodyNode.call && resolveMemberExpression(bodyNode.callee) === 'JSON.stringify') {
       // Handled below via type check
    }

    if (bodyNode.type === 'CallExpression' &&
             resolveMemberExpression(bodyNode.callee) === 'JSON.stringify') {
        if (bodyNode.arguments.length > 0) {
            let objectNode = null;
            let objectAnalysisPath = path;
            if (bodyNode.arguments[0].type === 'ObjectExpression') {
                objectNode = bodyNode.arguments[0];
            } else if (bodyNode.arguments[0].type === 'Identifier') {
                const resolvedObject = resolveObjectExpressionFromIdentifier(path, bodyNode.arguments[0].name);
                if (resolvedObject && resolvedObject.node) {
                    objectNode = resolvedObject.node;
                    objectAnalysisPath = resolvedObject.analysisPath || path;
                }
            }

            if (objectNode && objectNode.type === 'ObjectExpression') {
                const data = {};
                const derivations = {};
                const fieldSources = {};
                objectNode.properties.forEach(p => {
                    if (p.type === 'ObjectProperty') {
                        const key = p.key.name || p.key.value;
                        const sourceInfo = buildPackingFieldSource(path, p.value, objectAnalysisPath);
                        fieldSources[key] = sourceInfo;
                        let val = sourceInfo.source_name || "unknown";
                        if (sourceInfo.source_type === 'literal') {
                            val = sourceInfo.literal_value;
                        }
                        if (sourceInfo.derivation && typeof val === 'string') {
                            derivations[val] = sourceInfo.derivation;
                        }
                        data[key] = val;
                    }
                });
                return { type: "json", structure: data, value_derivations: derivations, field_sources: fieldSources };
            }
        }
    }
    // Case C: Object Literal (axios raw object)
    else if (bodyNode.type === 'ObjectExpression') {
         const data = {};
         const derivations = {};
         const fieldSources = {};
         bodyNode.properties.forEach(p => {
            if (p.type === 'ObjectProperty') {
                const key = p.key.name || p.key.value;
                const sourceInfo = buildPackingFieldSource(path, p.value);
                fieldSources[key] = sourceInfo;
                let val = sourceInfo.source_name || "unknown";
                if (sourceInfo.source_type === 'literal') {
                    val = sourceInfo.literal_value;
                }
                if (sourceInfo.derivation && typeof val === 'string') {
                    derivations[val] = sourceInfo.derivation;
                }
                data[key] = val;
            }
        });
        return { type: "object", structure: data, value_derivations: derivations, field_sources: fieldSources };
    }

    // Case D: URLSearchParams (toString)
    if (bodyNode.call || (bodyNode.type === 'CallExpression' &&
        bodyNode.callee.type === 'MemberExpression' &&
        bodyNode.callee.property.name === 'toString')) {

        const objName = bodyNode.callee.object.name; // e.g. formData
        const init = resolveVariableInitNode(path, objName);
        if (init && init.node && init.node.type === 'NewExpression' &&
            resolveMemberExpression(init.node.callee) === 'URLSearchParams') {

            const params = {};
            const derivations = {};
            const fieldSources = {};
            const scope = path.scope;
            const binding = scope.getBinding(objName);

            if (binding) {
                binding.referencePaths.forEach(refPath => {
                    const parent = refPath.parentPath;
                    if (parent.isMemberExpression() && parent.node.property.name === 'append' &&
                        parent.parentPath.isCallExpression()) {
                        const appendArgs = parent.parentPath.node.arguments;
                        if (appendArgs.length >= 2) {
                             const key = appendArgs[0].value || "unknown";
                             const sourceInfo = buildPackingFieldSource(path, appendArgs[1]);
                             fieldSources[key] = sourceInfo;
                             const valName = sourceInfo.source_name || "unknown";
                             if (sourceInfo.derivation && typeof valName === 'string') {
                                 derivations[valName] = sourceInfo.derivation;
                             }
                             params[key] = valName;
                        }
                    }
                });
            }
            return { type: "url_search_params", structure: params, value_derivations: derivations, field_sources: fieldSources };
        }
    }

    return null;
}

// Traverse AST
traverse(ast, {
  // New: Visit Functions to capture structure and API calls
  Function(path) {
      const funcName = getFunctionNameFromNode(path);
      const apiCalls = [];
      const cryptoCalls = [];

      // Local traversal for API calls within this function
      path.traverse({
          CallExpression(innerPath) {
              const callee = innerPath.node.callee;
              const fullCall = resolveMemberExpression(callee);

              // Detect API Calls (fetch, axios, ajax)
              if (fullCall === 'fetch' || fullCall.startsWith('axios') || fullCall.includes('ajax') || fullCall === 'XMLHttpRequest') {
                   // Try to get URL argument
                   let urlArg = "unknown";
                   if (innerPath.node.arguments.length > 0) {
                       const arg0 = innerPath.node.arguments[0];
                       if (arg0.type === 'StringLiteral') {
                           urlArg = arg0.value;
                       }
                   }
                   apiCalls.push(urlArg);

                   // NEW: Detect Payload Packing (how data is put into body)
                   const packInfo = detectPayloadPacking(innerPath, fullCall);
                   if (packInfo) {
                       findings.push({
                           library: 'Network',
                           algorithm: 'PayloadPacking',
                           operation: 'pack',
                           line: innerPath.node.loc ? innerPath.node.loc.start.line : 99999, // Use logic line or very high number if unlocatable
                           function: funcName,
                           code: generate(innerPath.node).code,
                           details: [ { operation: "pack", info: packInfo, line: innerPath.node.loc ? innerPath.node.loc.start.line : 99999 } ]
                       });
                   }
              }

              // Capture Crypto Calls strictly for mapping (simplified)
              if (fullCall.includes('encrypt') || fullCall.includes('decrypt') || fullCall.includes('sign') || fullCall.includes('digest')) {
                  cryptoCalls.push(fullCall);
              }
          }
      });

      functions.push({
          name: funcName,
          line: path.node.loc ? path.node.loc.start.line : 0,
          api_calls: apiCalls,
          crypto_calls: cryptoCalls
      });
  },

  CallExpression(path) {
    const callee = path.node.callee;
    const fullCall = resolveMemberExpression(callee);

    // 0. Intelligent Object Tracking (Scope-based)
    if (path.node.callee.type === 'MemberExpression') {
        const objectNode = path.node.callee.object;
        if (objectNode.type === 'Identifier') {
            const varName = objectNode.name;
            const binding = path.scope.getBinding(varName);

            if (binding) {
                // Check if initialized with known library
                if (binding.path.isVariableDeclarator() && binding.path.node.init) {
                    const init = binding.path.node.init;
                    if (init.type === 'NewExpression') {
                        const className = resolveMemberExpression(init.callee);

                        if (className === 'JSEncrypt') {
                             const method = path.node.callee.property.name;
                             if (method === 'setPublicKey') {
                                 // 增强提取逻辑 (复用底部的逻辑)
                                 let keyVal = null;
                                 let keyContext = "";
                                 if (path.node.arguments.length > 0) {
                                     const arg = path.node.arguments[0];
                                     if (t.isStringLiteral(arg)) {
                                         keyVal = arg.value;
                                         keyContext = `Literal: "${arg.value.substring(0, 20)}..."`;
                                     } else if (t.isTemplateLiteral(arg)) {
                                         if (arg.quasis.length === 1) {
                                             keyVal = arg.quasis[0].value.raw;
                                             keyContext = `TemplateLiteral: "${keyVal.substring(0, 20)}..."`;
                                         }
                                     } else if (t.isIdentifier(arg)) {
                                         keyContext = `Variable: ${arg.name}`;
                                         keyVal = resolveVariableValue(path, arg.name);
                                         if (keyVal) keyContext += ` (Resolved)`;
                                     }
                                 }

                                 findings.push({
                                    library: 'JSEncrypt',
                                    algorithm: 'RSA',
                                    operation: 'setkey',
                                    method: 'setPublicKey',
                                    line: path.node.loc ? path.node.loc.start.line : 0,
                                    function: getFunctionName(path),
                                    code: generate(path.node).code,
                                    details: [{
                                        operation: "setkey",
                                        line: path.node.loc ? path.node.loc.start.line : 0,
                                        context: keyContext,
                                        resolved_value: keyVal
                                    }]
                                });
                                return; // Handled
                             }
                             if (method === 'encrypt') {
                                 const outputVar = getOutputVariable(path);

                                 // New: Infer payload structure for RSA encrypt
                                 const details = [{
                                    operation: 'encrypt',
                                    line: path.node.loc ? path.node.loc.start.line : 0,
                                    context: generate(path.node).code,
                                    output_variable: outputVar
                                 }];
                                 if (path.get('arguments.0') && path.get('arguments.0').node) {
                                     enrichDetailWithInputMetadata(details[0], path, path.get('arguments.0'));
                                 }

                                 if (path.node.arguments.length > 0) {
                                     const dataNode = path.node.arguments[0];
                                     if (t.isIdentifier(dataNode)) {
                                         const schema = inferPayloadStructure(path, dataNode.name);
                                         // Find definition line for correct ordering
                                         const defLine = resolveVariableLine(path, dataNode.name);

                                         if (schema) {
                                             details.push({
                                                 operation: "DataStructure",
                                                 line: defLine > 0 ? defLine : path.node.loc.start.line,
                                                 context: `Inferred Payload Keys: ${JSON.stringify(schema)}`,
                                                 inferred_keys: schema
                                             });
                                         }
                                     }
                                 }

                                 findings.push({
                                    library: 'JSEncrypt',
                                    algorithm: 'RSA',
                                    operation: 'encrypt',
                                    method: 'encrypt',
                                    line: path.node.loc ? path.node.loc.start.line : 0,
                                    function: getFunctionName(path),
                                    code: generate(path.node).code,
                                    details: details
                                });
                                return; // Handled
                             }
                        }
                    }
                }
            }
        }
    }

    // 1. Detect Encryption Libraries

    // CryptoJS
    if (fullCall.startsWith('CryptoJS.')) {
      const parts = fullCall.split('.');
      // CryptoJS.AES.encrypt -> library=CryptoJS, algorithm=AES, operation=encrypt
      // CryptoJS.MD5('msg') -> library=CryptoJS, algorithm=MD5, operation=hash

      let algorithm = parts[1];
      let operation = 'unknown';

      if (['AES', 'DES', 'TripleDES', 'Rabbit', 'RC4', 'RC4Drop'].includes(algorithm)) {
          if (parts[2] === 'encrypt') operation = 'encrypt';
          else if (parts[2] === 'decrypt') operation = 'decrypt';
      } else if (['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA224', 'SHA384', 'RIPEMD160'].includes(algorithm)) {
          operation = 'hash';
      } else if (algorithm.startsWith('Hmac')) {
          operation = 'sign'; // HMAC
      }

      if (operation !== 'unknown') {
         const details = [];
         const args = path.node.arguments;
         const outputVar = getOutputVariable(path);
         const wrappedCryptoCall = t.isMemberExpression(path.node.callee) &&
             t.isIdentifier(path.node.callee.property, { name: 'toString' }) &&
             t.isCallExpression(path.node.callee.object)
             ? path.get('callee.object')
             : null;
         const cryptoArgs = wrappedCryptoCall ? wrappedCryptoCall.node.arguments : args;
         const dataArgPath = wrappedCryptoCall ? path.get('callee.object.arguments.0') : path.get('arguments.0');
         const keyArgPath = wrappedCryptoCall ? path.get('callee.object.arguments.1') : path.get('arguments.1');
         const outputTransform = wrappedCryptoCall ? generate(path.node).code : null;

         // 如果是加密/签名/哈希操作，尝试提取更详细的上下文 (Key/IV/Payload)
         if (['encrypt', 'decrypt', 'sign', 'hash'].includes(operation)) {
             // 1. Data (Payload) Analysis
             if (cryptoArgs.length > 0 && dataArgPath && dataArgPath.node) {
                 const dataNode = dataArgPath.node;
                 const targetNodes = [];

                 if (t.isIdentifier(dataNode)) {
                     targetNodes.push(dataNode);
                 } else if (t.isBinaryExpression(dataNode)) {
                     if (t.isIdentifier(dataNode.left)) targetNodes.push(dataNode.left);
                     if (t.isIdentifier(dataNode.right)) targetNodes.push(dataNode.right);
                 }

                 targetNodes.forEach(node => {
                     const schema = inferPayloadStructure(path, node.name);
                     const defLine = resolveVariableLine(path, node.name);

                     if (schema) {
                         details.push({
                             operation: "DataStructure",
                             line: defLine > 0 ? defLine : path.node.loc.start.line,
                             context: `Inferred Payload Keys for '${node.name}': ${JSON.stringify(schema)}`,
                             inferred_keys: schema
                         });
                     }
                 });
             }

             // 2. Key Analysis
             if (cryptoArgs.length > 1 && keyArgPath && keyArgPath.node) {
                 const keyNode = keyArgPath.node;
                 let resolvedKey = null;
                 let keyContext = "";
                 let definitionLine = 0;

                 if (t.isStringLiteral(keyNode)) {
                     resolvedKey = keyNode.value;
                     keyContext = `Literal: "${keyNode.value}"`;
                     definitionLine = path.node.loc.start.line;
                 } else if (t.isIdentifier(keyNode)) {
                     keyContext = `Variable: ${keyNode.name}`;
                     const res = resolveVariableValueWithLoc(path, keyNode.name);
                     if (res) {
                         resolvedKey = res.value;
                         definitionLine = res.line;
                         keyContext += ` (Resolved: "${resolvedKey}")`;
                     } else {
                         const derivation = traceVariableDerivation(path, keyNode.name);
                         if (derivation) {
                             definitionLine = resolveVariableLine(path, keyNode.name);
                             keyContext += ` (Derived)`;
                             details.push({
                                 operation: "derive_key",
                                 target: "key",
                                 line: definitionLine,
                                 derivation: derivation
                             });
                         } else {
                             definitionLine = path.node.loc.start.line;
                         }
                     }
                 }

                 if (resolvedKey) {
                     details.push({
                         operation: "setkey",
                         line: definitionLine > 0 ? definitionLine : path.node.loc.start.line,
                         context: keyContext,
                         resolved_value: resolvedKey
                     });
                 }
             }

             // 3. Options (IV) Analysis
             if (cryptoArgs.length > 2 && t.isObjectExpression(cryptoArgs[2])) {
                 cryptoArgs[2].properties.forEach(prop => {
                     if (t.isObjectProperty(prop) && t.isIdentifier(prop.key) && prop.key.name === 'iv') {
                         let resolvedIv = null;
                         let ivContext = "";
                         let definitionLine = 0;

                         if (t.isStringLiteral(prop.value)) {
                             resolvedIv = prop.value.value;
                             ivContext = `Literal: "${prop.value.value}"`;
                             definitionLine = prop.loc.start.line;
                         } else if (t.isIdentifier(prop.value)) {
                             ivContext = `Variable: ${prop.value.name}`;
                             const res = resolveVariableValueWithLoc(path, prop.value.name);
                             if (res) {
                                 resolvedIv = res.value;
                                 definitionLine = res.line;
                                 ivContext += ` (Resolved: "${resolvedIv}")`;
                             } else {
                                 // 尝试追踪衍生逻辑 (IV)
                                 const derivation = traceVariableDerivation(path, prop.value.name);
                                 if (derivation) {
                                     definitionLine = resolveVariableLine(path, prop.value.name);
                                     ivContext += ` (Derived)`;
                                     details.push({
                                         operation: "derive_iv",
                                         target: "iv",
                                         line: definitionLine,
                                         derivation: derivation
                                     });
                                 } else {
                                     definitionLine = prop.loc.start.line;
                                 }
                             }
                         }

                         if (resolvedIv) {
                             details.push({
                                 operation: "setiv",
                                 line: definitionLine > 0 ? definitionLine : prop.loc.start.line,
                                 context: ivContext,
                                 resolved_value: resolvedIv
                             });
                         }
                     }
                 });
             }
         }

         // 添加基础操作记录
         const opDetail = {
            operation: operation,
            line: path.node.loc ? path.node.loc.start.line : 0,
            context: generate(path.node).code,
            output_variable: outputVar
         };
         if (outputTransform) {
            opDetail.output_transform = outputTransform;
         }
         if (dataArgPath && dataArgPath.node) {
            enrichDetailWithInputMetadata(opDetail, path, dataArgPath);
         }
         details.push(opDetail);

         findings.push({
          library: 'CryptoJS',
          algorithm: algorithm,
          operation: operation,
          line: path.node.loc ? path.node.loc.start.line : 0,
          function: getFunctionName(path),
          code: generate(path.node).code,
          details: details // 附加详细信息
        });
      }
    }

    // JSEncrypt (RSA)
    if (fullCall.endsWith('.setPublicKey')) {
       // 增强: 提取公钥值 (resolved_value)
       let keyVal = null;
       let keyContext = "";

       if (path.node.arguments.length > 0) {
           const arg = path.node.arguments[0];
           if (t.isStringLiteral(arg)) {
               keyVal = arg.value;
               keyContext = `Literal: "${arg.value.substring(0, 20)}..."`;
           } else if (t.isTemplateLiteral(arg)) {
               // 直接传入的 TemplateLiteral (多行字符串)
               if (arg.quasis.length === 1) {
                   keyVal = arg.quasis[0].value.raw;
                   keyContext = `TemplateLiteral: "${keyVal.substring(0, 20)}..."`;
               }
           } else if (t.isIdentifier(arg)) {
               keyContext = `Variable: ${arg.name}`;
               keyVal = resolveVariableValue(path, arg.name);
               if (keyVal) keyContext += ` (Resolved)`;
           }
       }

       findings.push({
          library: 'JSEncrypt',
          algorithm: 'RSA',
          operation: 'setkey',
          line: path.node.loc ? path.node.loc.start.line : 0,
          function: getFunctionName(path),
          code: generate(path.node).code,
          // 添加 details 以传递 resolved_value
          details: [{
              operation: "setkey",
              line: path.node.loc ? path.node.loc.start.line : 0,
              context: keyContext,
              resolved_value: keyVal
          }]
        });
    }

    // WebCrypto API (SubtleCrypto)
    if (fullCall.includes('subtle.encrypt') || fullCall.includes('subtle.decrypt') || fullCall.includes('subtle.sign')) {
        let op = 'unknown';
        if (fullCall.includes('encrypt')) op = 'encrypt';
        else if (fullCall.includes('decrypt')) op = 'decrypt';
        else if (fullCall.includes('sign')) op = 'sign';

        findings.push({
            library: 'WebCrypto',
            algorithm: 'Dynamic (SubtleCrypto)',
            operation: op,
            line: path.node.loc ? path.node.loc.start.line : 0,
            function: getFunctionName(path),
            code: generate(path.node).code
        });
    }

    // Heuristics for JSEncrypt or generic encrypt methods
    // Matches var.encrypt(...) where var isn't CryptoJS/Subtle
    if (callee.type === 'MemberExpression' && callee.property.name === 'encrypt') {
        const objectName = resolveMemberExpression(callee.object);
        if (!objectName.startsWith('CryptoJS') && !objectName.includes('subtle') && !objectName.includes('AES') && !objectName.includes('DES')) {
             // 增强：尝试推断 RSA 加密的 Payload
             const details = [];
             if (path.node.arguments.length > 0) {
                 const dataNode = path.node.arguments[0];

                 // 1. 如果是 toString() 调用，如 rsa.encrypt(key.toString())，尝试追踪 key
                 if (t.isCallExpression(dataNode) &&
                     t.isMemberExpression(dataNode.callee) &&
                     dataNode.callee.property.name === 'toString') {
                     // 暂不深入，简单记录
                 }
                 // 2. 如果是标识符，尝试推断结构
                 else if (t.isIdentifier(dataNode)) {
                     const schema = inferPayloadStructure(path, dataNode.name);
                     if (schema) {
                         details.push({
                             operation: "DataStructure",
                             line: path.node.loc.start.line,
                             context: `Inferred Payload Keys: ${JSON.stringify(schema)}`,
                             inferred_keys: schema
                         });
                     }
                 }
             }

             findings.push({
                library: 'Generic (Possible JSEncrypt)',
                algorithm: 'RSA/Unknown',
                operation: 'encrypt',
                line: path.node.loc ? path.node.loc.start.line : 0,
                function: getFunctionName(path),
                code: generate(path.node).code,
                details: details.length > 0 ? details : undefined
             });
        }
    }
  },

  NewExpression(path) {
      const callee = path.node.callee;
      const name = resolveMemberExpression(callee);
      if (name === 'JSEncrypt') {
          findings.push({
              library: 'JSEncrypt',
              algorithm: 'RSA',
              operation: 'init',
              line: path.node.loc ? path.node.loc.start.line : 0,
              function: getFunctionName(path),
              code: generate(path.node).code
          });
      }
  },

  // Hardcoded Keys Detection
  VariableDeclarator(path) {
      const id = path.node.id;
      const init = path.node.init;

      if (id.type === 'Identifier' && init && (init.type === 'StringLiteral' || init.type === 'NumericLiteral')) {
          const name = id.name.toLowerCase();
          const value = init.value;

          // Pattern: variables named key, secret, iv, salt, pass
          // AND value length > 8 (to avoid 'key': 'id')
          if (/(key|secret|password|passwd|iv|salt|token)/.test(name)) {
              if (String(value).length >= 8) {
                   findings.push({
                      library: 'N/A',
                      algorithm: 'N/A',
                      operation: 'hardcoded_secret',
                      weakness: 'HARDCODED_KEY',
                      line: path.node.loc ? path.node.loc.start.line : 0,
                      function: getFunctionName(path),
                      code: `${id.name} = "${String(value).substring(0, 5)}..."` // Truncate for report
                  });
              }
          }
      }
  },

  // Object Property Keys (e.g. { key: "..." })
  ObjectProperty(path) {
      const key = path.node.key;
      const value = path.node.value;

      if ((key.name || key.value) && (value.type === 'StringLiteral')) {
           const name = (key.name || key.value).toLowerCase();
           const valStr = value.value;

           if (/(key|secret|password|passwd|iv|salt|token)/.test(name)) {
              if (valStr.length >= 8) {
                   findings.push({
                      library: 'N/A',
                      algorithm: 'N/A',
                      operation: 'hardcoded_secret',
                      weakness: 'HARDCODED_KEY',
                      line: path.node.loc ? path.node.loc.start.line : 0,
                      function: getFunctionName(path),
                      code: `${key.name || key.value}: "${valStr.substring(0, 5)}..."`
                  });
              }
          }
      }
  }
});

// Output
const result = {
  file: options.input,
  findings: findings,
  functions: functions // Export functions
};

if (options.output) {
    fs.writeFileSync(options.output, JSON.stringify(result, null, 2));
} else {
    console.log(JSON.stringify(result, null, 2));
}