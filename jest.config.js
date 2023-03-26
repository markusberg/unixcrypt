module.exports = {
  "transform": {
    "^.+\\.ts$": "ts-jest"
  },
  "testMatch": [
    "<rootDir>/test/**/*.spec.ts",
  ],
  "moduleFileExtensions": [
    "ts",
    "tsx",
    "js",
    "jsx",
    "json",
    "node"
  ],
  "modulePathIgnorePatterns": [
    "<rootDir>/dist"
  ],
  "coverageReporters": ['json-summary', 'text']
};
