// A stand-in for PagerDuty's Custom Event Transformer runtime, for the tests only (fakes.py and
// test_monitoring_transform.py). Reads {"code": "...", "body": ...} on stdin, runs the code in an empty context that
// holds nothing but a stub PD object, and prints {"events": [...], "cef": [...], "failed": null | "...",
// "error": null | "..."}.
"use strict";
var vm = require("vm");

var input = JSON.parse(require("fs").readFileSync(0, "utf8"));
var result = { events: [], cef: [], failed: null, error: null };
var PD = {
  Trigger: "trigger",
  Resolve: "resolve",
  Acknowledge: "acknowledge",
  inputRequest: { body: input.body, rawBody: JSON.stringify(input.body), headers: {} },
  emitGenericEvents: function (events) { result.events = result.events.concat(events); },
  emitCEFEvents: function (events) { result.cef = result.cef.concat(events); },
  fail: function (message) { result.failed = String(message); }
};
try {
  vm.runInNewContext(input.code, { PD: PD }, { timeout: 5000 });
} catch (e) {
  result.error = String(e);
}
process.stdout.write(JSON.stringify(result));
