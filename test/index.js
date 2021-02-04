const {
  TestSet,
  TestRunner
} = require('alsatian');
const {
  TapBark
} = require('tap-bark');

const testSet = TestSet.create();

testSet.addTestsFromFiles("./test/*.test.js");

const testRunner = new TestRunner;

testRunner.outputStream.pipe(TapBark.create().getPipeable()).pipe(process.stdout);

testRunner.run(testSet);