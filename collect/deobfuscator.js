const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');
const fs = require('fs');
const { program } = require('commander');
program
  .requiredOption('-i, --input <path>', 'Input JS file path')
  .requiredOption('-o, --output <path>', 'Output JS file path')
  .option('--no-formatting', 'Disable code formatting')
  .parse(process.argv);
const options = program.opts();
try {
  const code = fs.readFileSync(options.input, 'utf-8');
  let ast;
  try {
     ast = parser.parse(code, { sourceType: 'unambiguous', allowReturnOutsideFunction: true });
  } catch(e) {
     try {
       ast = parser.parse('function _wrapped(){' + code + '}', { sourceType: 'script' });
     } catch (e2) {
       ast = parser.parse(code, { sourceType: 'script', allowReturnOutsideFunction: true });
     }
  }
  traverse(ast, {
    StringLiteral(path) {
      if (path.node.extra) delete path.node.extra;
    },
    NumericLiteral(path) {
        if (path.node.extra) delete path.node.extra;
    }
  });
  const output = generate(ast, {
    compact: options.formatting === false, 
    comments: options.formatting !== false
  }, code);
  fs.writeFileSync(options.output, output.code);
  console.log('Deobfuscation complete');
} catch (e) {
  console.error('Error:', e.message);
  process.exit(1);
}