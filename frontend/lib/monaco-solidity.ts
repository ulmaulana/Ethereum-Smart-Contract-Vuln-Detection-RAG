import type * as Monaco from "monaco-editor";

let registered = false;

export const VS_LIGHT_THEME = "vs-light-active-line";
export const VS_DARK_THEME = "vs-dark-active-line";

export function registerSolidityLanguage(monaco: typeof Monaco) {
  if (registered) return;
  registered = true;

  monaco.editor.defineTheme(VS_LIGHT_THEME, {
    base: "vs",
    inherit: true,
    rules: [],
    colors: {
      "editor.lineHighlightBackground": "#eef0f4",
      "editor.lineHighlightBorder": "#00000000",
    },
  });

  monaco.editor.defineTheme(VS_DARK_THEME, {
    base: "vs-dark",
    inherit: true,
    rules: [],
    colors: {
      "editor.lineHighlightBackground": "#2a2d2e",
      "editor.lineHighlightBorder": "#00000000",
    },
  });

  monaco.languages.register({
    id: "solidity",
    extensions: [".sol"],
    aliases: ["Solidity", "solidity"],
  });

  monaco.languages.setLanguageConfiguration("solidity", {
    comments: { lineComment: "//", blockComment: ["/*", "*/"] },
    brackets: [
      ["{", "}"],
      ["[", "]"],
      ["(", ")"],
    ],
    autoClosingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"', notIn: ["string"] },
      { open: "'", close: "'", notIn: ["string", "comment"] },
    ],
    surroundingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
      { open: "'", close: "'" },
    ],
  });

  const intSizes = Array.from({ length: 32 }, (_, i) => (i + 1) * 8);
  const intTypes = ["int", "uint", ...intSizes.flatMap((s) => [`int${s}`, `uint${s}`])];
  const bytesTypes = ["bytes", ...Array.from({ length: 32 }, (_, i) => `bytes${i + 1}`)];

  monaco.languages.setMonarchTokensProvider("solidity", {
    defaultToken: "",
    tokenPostfix: ".sol",

    keywords: [
      "pragma", "solidity", "import", "as", "from", "contract", "library", "interface",
      "abstract", "is", "using", "function", "modifier", "event", "error", "struct",
      "enum", "mapping", "constructor", "fallback", "receive", "return", "returns",
      "public", "private", "internal", "external", "payable", "view", "pure", "virtual",
      "override", "constant", "immutable", "memory", "storage", "calldata", "if", "else",
      "for", "while", "do", "break", "continue", "require", "revert", "assert", "emit",
      "new", "delete", "try", "catch", "throw", "unchecked", "assembly", "let", "this",
      "super", "indexed", "anonymous",
    ],

    typeKeywords: ["address", "bool", "string", "byte", "var", "fixed", "ufixed", ...intTypes, ...bytesTypes],

    constants: ["true", "false", "null", "wei", "gwei", "ether", "seconds", "minutes", "hours", "days", "weeks"],

    operators: [
      "=", "!", "~", "?", ":", "==", "<=", ">=", "!=", "&&", "||", "++", "--",
      "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>",
      "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>=", "=>",
    ],

    symbols: /[=><!~?:&|+\-*/^%]+/,
    escapes: /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4})/,

    tokenizer: {
      root: [
        [
          /[a-zA-Z_$][\w$]*/,
          {
            cases: {
              "@typeKeywords": "type",
              "@keywords": "keyword",
              "@constants": "constant",
              "@default": "identifier",
            },
          },
        ],
        { include: "@whitespace" },
        [/[{}()\[\]]/, "@brackets"],
        [
          /@symbols/,
          {
            cases: {
              "@operators": "operator",
              "@default": "",
            },
          },
        ],
        [/\d*\.\d+([eE][\-+]?\d+)?/, "number.float"],
        [/0[xX][0-9a-fA-F]+/, "number.hex"],
        [/\d+/, "number"],
        [/[;,.]/, "delimiter"],
        [/"([^"\\]|\\.)*$/, "string.invalid"],
        [/"/, "string", "@string_double"],
        [/'([^'\\]|\\.)*$/, "string.invalid"],
        [/'/, "string", "@string_single"],
      ],
      comment: [
        [/[^/*]+/, "comment"],
        [/\/\*/, "comment", "@push"],
        [/\*\//, "comment", "@pop"],
        [/[/*]/, "comment"],
      ],
      whitespace: [
        [/[ \t\r\n]+/, ""],
        [/\/\*/, "comment", "@comment"],
        [/\/\/.*$/, "comment"],
      ],
      string_double: [
        [/[^\\"]+/, "string"],
        [/@escapes/, "string.escape"],
        [/\\./, "string.escape.invalid"],
        [/"/, "string", "@pop"],
      ],
      string_single: [
        [/[^\\']+/, "string"],
        [/@escapes/, "string.escape"],
        [/\\./, "string.escape.invalid"],
        [/'/, "string", "@pop"],
      ],
    },
  });
}
