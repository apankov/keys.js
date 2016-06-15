module.exports = function () {
  return {
    files: [
      'lib/*.js',
      {pattern: 'lib/*.pegjs', instrument: false}
    ],

    tests: [
      'test/unit/*.js'
    ],

    env: {
      type: 'node'
    },

    testFramework: 'mocha'
  }
}
