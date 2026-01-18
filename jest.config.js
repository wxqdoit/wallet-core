/** @type {import('ts-jest').JestConfigWithTsJest} **/
export default {
  testEnvironment: "node",
  transform: {
    "^.+\\.tsx?$": ["ts-jest",{}],
    "^.+\\.jsx?$": ["ts-jest",{}],
  },
  transformIgnorePatterns: [
    "node_modules/(?!(@scure|@noble)/)"
  ],
};