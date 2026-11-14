// trellis-watchtower: the code of each TPA PagerDuty service's "Google Cloud Monitoring (titled)" integration
// (PagerDuty's Custom Event Transformer). docs/PAGERDUTY.md, "Incident titles".
//
// PagerDuty runs this once for each request Cloud Monitoring posts to the integration. It turns Monitoring's
// notification into one event with a short title, a small set of plainly named details read top to bottom, and
// links to the watchtower. Nothing is fetched and nothing outside the notification is added, except the watchtower's
// address. The alerts carry no PHI and this adds none.
//
// scripts/pagerduty/pd_setup.py stores this file's text in PagerDuty, with the placeholder in WATCHTOWER below
// replaced by pdlib.WATCHTOWER_URL, and corrects PagerDuty whenever the two differ: change the file, never the code
// in PagerDuty's screen.
//
// ES5 only, and ASCII only: no let, const, arrow function, template string or trailing comma, and the middle dot
// is written \u00b7. tests/pagerduty/test_monitoring_transform.py runs this file under node and refuses the rest.

var WATCHTOWER = "__WATCHTOWER_URL__";
var SEPARATOR = " \u00b7 ";
var DASH = "\u2013";
var TITLE_LIMIT = 250;
var ACTION_LIMIT = 80;

// Whether anyone needs to act (the owner, 2026-11-14: "why are they not descriptive on the problem"). An alert that
// pages (Critical, Error, or a severity the services' rules do not map, which pages at high urgency, PagerDuty's
// default) always ends "check now", whatever its subject says. A Warning ends with its subject's own words
// (tpa-platform's "<what happened> \u00b7 <whether to act>", the policy's own or its tier's: "look today", "no action
// needed"), or, for a subject from before that or Monitoring's own words, "look today" (a change group: the deploy
// words).
var ACT_NOW = "check now";
var ACT_TODAY = "look today";
var DEPLOY_ACTION = "expected during a deploy; check the deploy notes";
// A test event's mark, kept at the front of every title so a test reads as one in Slack.
var TEST_MARK = /^TEST \(ignore\): /;
var URGENT_MARK = /^URGENT /;

// Monitoring's tag in front of a subject: "[ALERT - Warning] ", "[RESOLVED] ". At most one is dropped.
var TAG = /^\[[^\]]*\] /;
// A subject of ours after the tag: tpa-platform's "<word> \u00b7 <what happened>", the word the environment's
// ("beta", "production-full") or the estate's name where the environment word must not show ("TPA": the production
// root is named beta, the owner, 2026-11-12: "We are NOT in beta"). Monitoring's own subject for a policy without
// one ("<condition> on <resource>") has no such shape and is not used.
var OUR_SUBJECT = /^[A-Za-z][A-Za-z-]* \u00b7 /;

// The watchtower's pages (cloud/dashboards: each is at <watchtower>/d/<uid>).
var OVERVIEW = { uid: "tw-cloud-overview", name: "overview" };
var SERVICE_UID = "tw-cloud-service-";
// The Cloud Run services that have a page of their own (cloud/dashboards/service-<name>.json).
var SERVICE_PAGES = [
  "auth", "auth-event-publisher", "auth-outbox-publisher", "connectors", "crm-web", "engine", "model-gateway",
  "ops-web", "records", "svc-ops", "svc-twilio-rest", "svc-voice", "tpa-api", "tpa-jobs-drains", "watchtower", "web"
];
// The page for an alert, from the alert alone. The first row that matches wins. `words` are looked for, in lower
// case, in the metric type, the resource type, the policy and condition names and the subject.
var PAGES_BY_WORDS = [
  { uid: "tw-cloud-jobs", name: "Jobs", words: ["tpa_jobs", "tpa-jobs", "cloud_run_job", "cloud_scheduler_job"] },
  { uid: "tw-cloud-databases", name: "Databases", words: ["cloudsql"] },
  { uid: "tw-cloud-sign-in", name: "Sign-in", words: ["auth_", "sign-in"] }
];
// Then a Cloud Run service with a page of its own (SERVICE_PAGES), and then the project, by the end of its id.
var PAGES_BY_PROJECT = [
  { uid: "tw-cloud-portal-api", name: "Portal & API", ending: "-tpa-app" },
  { uid: "tw-cloud-records", name: "Member records", ending: "-tpa-phi" },
  { uid: "tw-cloud-callcentre", name: "Call centre", ending: "-cc" }
];

// One problem, one page (2026-11-14, deploy-safety). This account's plan has no alert grouping (no time-based,
// content-based or intelligent grouping, no AIOps: read from its /abilities), so the grouping is the Events API's own:
// an event whose incident_key names an incident that is still open is added to that incident's alert log, and pages
// nobody a second time. Nothing is downgraded or dropped: the first event of a group opens its incident at its own
// severity, and the severity is in the key, so a Critical event never joins a Warning incident.
//   1. Control-plane changes: one change counter (an IAM policy or role, a firewall or Cloud Armor rule, an alert
//      policy or channel, a log metric) in one project, at one severity, within one two-hour UTC slot, is one incident:
//      an approved apply's many changes of one kind are one page, and a change of another kind still pages on its own
//      (a log metric narrowed during an IAM apply). These policies wait for a person (#202: they send no close); PHI's
//      Critical IAM change sends one, and its close resolves its group.
//   2. One Cloud Run service failing: its start-up, crash, memory and database-dial counters (run_system_errors,
//      run_crash_exits, run_oom_kills, sql_proxy_errors) for the same service or job, in one project, at one severity,
//      within one half-hour UTC slot, are one incident. Its close is left to a person: one counter going quiet must
//      not resolve an incident whose other counters still fire (an open real problem stays open).
// A slot starts on the hour (or the half hour, or the even hour) in UTC, from Monitoring's started_at; a group that
// crosses a slot's end is two incidents, never none. An event with no started_at is not grouped.
// A group's title is its own, in plain words (the owner, 2026-11-14: "I have no idea what these are"): "Portal & API
// settings changed during 10:00\u201312:00 UTC (an alert counter was updated) \u00b7 expected during a deploy; check
// the deploy notes", and "The records service is failing during 02:00\u201302:30 UTC (it crashed) \u00b7 look today".
// Its whether-to-act follows act() above: "check now" when it pages, else the subject's own, else the deploy words for
// a change and "look today" for a failure.
var GROUP_PREFIX = "logging.googleapis.com/user/";
var CHANGE_METRICS = ["iam_policy_changes", "network_control_changes", "monitoring_changes", "log_metric_changes"];
var CHANGE_SLOT_SECONDS = 2 * 3600;
var SERVICE_METRICS = ["run_system_errors", "run_crash_exits", "run_oom_kills", "sql_proxy_errors"];
var SERVICE_SLOT_SECONDS = 30 * 60;

function text(value) {
  if (value === null || value === undefined) { return ""; }
  return String(value).replace(/^\s+|\s+$/g, "");
}

function field(object, name) {
  return object && typeof object === "object" ? object[name] : undefined;
}

function endsWith(value, ending) {
  return value.length >= ending.length && value.substring(value.length - ending.length) === ending;
}

function contains(list, value) {
  var n;
  for (n = 0; n < list.length; n++) {
    if (list[n] === value) { return true; }
  }
  return false;
}

// The title a person reads. The environment word in front is dropped: this account pages for one estate, the
// production one, whose Terraform root happens to be named "beta" (the owner, 2026-11-12: "We are NOT in beta").
// A Google operation name ("google.monitoring.v3.AlertPolicyService.DeleteAlertPolicy") becomes its last part in
// words ("delete alert policy"). The first letter is a capital.
var OPERATION = /google\.[A-Za-z0-9.]+\.([A-Z][A-Za-z]+)\b/g;

function plain(subject) {
  var out = subject.replace(OPERATION, function (whole, last) {
    return last.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
  });
  return out.charAt(0).toUpperCase() + out.substring(1);
}

function cut(value, limit) {
  return value.length > limit ? value.substring(0, limit - 3) + "..." : value;
}

function pages(i) {
  return text(i.severity).toLowerCase() !== "warning";
}

// Whether to act: "check now" for an alert that pages; else the subject's own words, else `otherwise`.
function act(i, h, otherwise) {
  if (pages(i)) { return ACT_NOW; }
  return h.own ? h.tail : otherwise;
}

// Our subject after its word, in plain words, or null when the subject is not ours.
function ours(i) {
  var subject = text(field(i.documentation, "subject")).replace(TAG, "");
  if (!OUR_SUBJECT.test(subject)) { return null; }
  return text(plain(subject.replace(OUR_SUBJECT, ""))) || null;
}

// What a person reads, as { what, tail, own, action }: what happened; the subject's own whether-to-act (`tail`, when
// `own`: its last part, after the last separator, as what happened may hold one, "TPA \u00b7 Portal & API"); and
// whether anyone needs to act for an alert outside the groups (act above).
function heading(i) {
  var body = ours(i);
  var policy = text(i.policy_name);
  var condition = text(i.condition_name);
  var h, at;
  if (body !== null) {
    at = body.lastIndexOf(SEPARATOR);
    h = at === -1 ? { what: body, tail: "", own: false } :
      { what: body.substring(0, at), tail: body.substring(at + SEPARATOR.length), own: true };
  } else if (policy && condition) {
    h = { what: policy + SEPARATOR + condition, tail: "", own: false };
  } else {
    h = { what: text(i.summary) || "Cloud Monitoring alert", tail: "", own: false };
  }
  h.action = act(i, h, ACT_TODAY);
  return h;
}

// The title: what happened, cut so that whether to act always shows, then whether to act (itself cut at
// ACTION_LIMIT, so what happened always has room).
function titled(what, action) {
  var end = action ? SEPARATOR + cut(action, ACTION_LIMIT) : "";
  return cut(what, TITLE_LIMIT - end.length) + end;
}

function page(i) {
  var resource = field(i, "resource");
  var labels = field(resource, "labels");
  var words = [
    text(field(i.metric, "type")), text(field(resource, "type")), text(i.policy_name), text(i.condition_name),
    text(field(i.documentation, "subject"))
  ].join(" ").toLowerCase();
  var service = text(field(labels, "service_name"));
  var project = text(field(labels, "project_id")) || text(i.scoping_project_id);
  var n, w;
  for (n = 0; n < PAGES_BY_WORDS.length; n++) {
    for (w = 0; w < PAGES_BY_WORDS[n].words.length; w++) {
      if (words.indexOf(PAGES_BY_WORDS[n].words[w]) !== -1) { return PAGES_BY_WORDS[n]; }
    }
  }
  if (contains(SERVICE_PAGES, service)) { return { uid: SERVICE_UID + service, name: service + " service" }; }
  for (n = 0; n < PAGES_BY_PROJECT.length; n++) {
    if (endsWith(project, PAGES_BY_PROJECT[n].ending)) { return PAGES_BY_PROJECT[n]; }
  }
  return OVERVIEW;
}

function link(uid) {
  return WATCHTOWER + "/d/" + uid;
}

function two(n) {
  return n < 10 ? "0" + n : String(n);
}

// Monitoring's time (seconds since 1970) as "2026-11-12T05:28:39Z"; "" when it is not a time.
function when(seconds) {
  var n = Number(seconds);
  var d;
  if (seconds === null || seconds === undefined || seconds === "" || !isFinite(n) || n <= 0) { return ""; }
  d = new Date(n * 1000);
  return d.getUTCFullYear() + "-" + two(d.getUTCMonth() + 1) + "-" + two(d.getUTCDate()) + "T" +
    two(d.getUTCHours()) + ":" + two(d.getUTCMinutes()) + ":" + two(d.getUTCSeconds()) + "Z";
}

function measured(i) {
  var observed = text(i.observed_value);
  var threshold = text(i.threshold_value);
  if (observed && threshold) { return observed + " (threshold " + threshold + ")"; }
  return observed;
}

function metric(i) {
  var labels = field(i.metric, "labels");
  var names = [];
  var pairs = [];
  var name, n;
  if (labels && typeof labels === "object") {
    for (name in labels) {
      if (Object.prototype.hasOwnProperty.call(labels, name)) { names.push(name); }
    }
  }
  names.sort();
  for (n = 0; n < names.length; n++) { pairs.push(names[n] + "=" + text(labels[names[n]])); }
  return text(field(i.metric, "type")) + (pairs.length ? " {" + pairs.join(", ") + "}" : "");
}

// The details, in reading order. A field with nothing to say is left out. `incident` is Monitoring's own object,
// unchanged: the services' severity rules read event.custom_details.incident.severity (pdlib.SEVERITY_FIELD).
// `what_to_check` is the policy's own documentation: what the alert means and what to read.
function details(i, h, best) {
  var all = [
    ["what_happened", h.what],
    ["what_to_do", h.action],
    ["what_to_check", text(field(i.documentation, "content"))],
    ["dashboard", link(best.uid)],
    ["overview", link(OVERVIEW.uid)],
    ["project", text(field(field(i.resource, "labels"), "project_id")) || text(i.scoping_project_id)],
    ["severity", text(i.severity)],
    ["measured", measured(i)],
    ["where", text(i.resource_type_display_name)],
    ["metric", metric(i)],
    ["policy", text(i.policy_name)],
    ["condition", text(i.condition_name)],
    ["started", when(i.started_at)],
    ["ended", when(i.ended_at)],
    ["console", text(i.url)],
    ["monitoring_summary", text(i.summary)]
  ];
  var made = {};
  var n;
  for (n = 0; n < all.length; n++) {
    if (all[n][1]) { made[all[n][0]] = all[n][1]; }
  }
  made.incident = i;
  return made;
}

function contexts(i, best) {
  var links = [{ type: "link", href: link(best.uid), text: "Watchtower: " + best.name }];
  if (best.uid !== OVERVIEW.uid) {
    links.push({ type: "link", href: link(OVERVIEW.uid), text: "Watchtower: overview" });
  }
  if (text(i.url)) { links.push({ type: "link", href: text(i.url), text: "Cloud Monitoring incident" }); }
  return links;
}

// Monitoring's notification is {"incident": {...}, "version": "1.2"}. An Events API v1 event that carries the same
// object in its details ({"details": {"incident": {...}}}) is read too.
function incidentOf(body) {
  var found;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch (e) { return null; }
  }
  found = field(body, "incident") || field(field(body, "details"), "incident");
  if (!found || typeof found !== "object" || Object.prototype.toString.call(found) === "[object Array]") {
    return null;
  }
  return found;
}

// "02:00" for a slot's start.
function clock(seconds) {
  var d = new Date(seconds * 1000);
  return two(d.getUTCHours()) + ":" + two(d.getUTCMinutes());
}

// The part of the estate a project is, in the words the watchtower's pages use; "Production" when it is none of them.
function area(project) {
  var n;
  for (n = 0; n < PAGES_BY_PROJECT.length; n++) {
    if (endsWith(project, PAGES_BY_PROJECT[n].ending)) { return PAGES_BY_PROJECT[n].name; }
  }
  return "Production";
}

// A Google method's name in lower-case words: "SetIAMPolicy" is ["set", "iam", "policy"], "addRule" ["add", "rule"].
function words(name) {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2").toLowerCase()
    .split(" ");
}

// A method's first word as what happened to the thing; "changed" for any other.
var DONE = {
  create: "created", insert: "created", add: "added", update: "updated", patch: "changed", set: "changed",
  "delete": "deleted", remove: "removed", undelete: "restored", enable: "turned on", disable: "turned off",
  destroy: "destroyed", replace: "replaced", rename: "renamed"
};

function done(verb) {
  return Object.prototype.hasOwnProperty.call(DONE, verb) ? DONE[verb] : "changed";
}

// Where an IAM change was made, from the service in its operation's name; "" when it does not say.
var IAM_PLACES = [
  [".run.", " on a Cloud Run service"], ["secretmanager", " on a secret"], ["storage.", " on a storage bucket"],
  ["iam.admin", " on a service account"], [".kms.", " on an encryption key"]
];

function place(operation) {
  var n;
  if (operation.indexOf(".run.") !== -1 && operation.indexOf("Jobs.") !== -1) { return " on a Cloud Run job"; }
  for (n = 0; n < IAM_PLACES.length; n++) {
    if (operation.indexOf(IAM_PLACES[n][0]) !== -1) { return IAM_PLACES[n][1]; }
  }
  return "";
}

// One control-plane change in plain words, from its counter and its operation label (the method Google logged:
// "google.logging.v2.MetricsServiceV2.UpdateLogMetric", "v1.compute.networkFirewallPolicies.addRule",
// "storage.setIamPermissions", or a bare "SetIamPolicy"). A method these words do not know reads as its kind of
// change: the operation itself is in the alert's details either way.
function changed(name, operation) {
  var parts = operation.split(".");
  var method = parts[parts.length - 1] || "";
  var collection = parts.length > 1 ? parts[parts.length - 2] : "";
  var w = words(method);
  var thing = w.slice(1).join(" ");
  var verb = done(w[0]);
  if (name === "log_metric_changes") { return "an alert counter was " + verb; }
  if (name === "monitoring_changes") {
    if (thing === "alert policy") { return "an alert policy was " + verb; }
    if (thing === "notification channel") { return "an alert channel was " + verb; }
    if (thing === "snooze") { return "alerts were snoozed"; }
    return "an alert policy or channel was " + verb;
  }
  if (name === "iam_policy_changes") {
    if (contains(w, "role")) { return "an access role was " + verb; }
    return "access rights were changed" + place(operation);
  }
  if (contains(w, "association")) {
    return (collection === "securityPolicies" ? "a Cloud Armor policy was " : "a firewall policy was ") +
      (w[0] === "add" ? "attached to a network" : w[0] === "remove" ? "detached from a network" :
        "changed where it applies");
  }
  if (contains(w, "rule")) {
    return (collection === "securityPolicies" ? "a Cloud Armor rule" : "a firewall rule") + " was " + verb;
  }
  if (collection === "securityPolicies") { return "a Cloud Armor policy was " + verb; }
  if (collection === "backendServices" && thing === "security policy") { return "a site's Cloud Armor policy was changed"; }
  if (collection === "firewalls") { return "a firewall rule was " + verb; }
  if (collection.toLowerCase().indexOf("firewall") !== -1) { return "a firewall policy was " + verb; }
  return "a firewall or Cloud Armor rule was changed";
}

// What one failing counter means, in plain words.
var FAILING = {
  run_system_errors: "it could not start or failed a health check",
  run_crash_exits: "it crashed",
  run_oom_kills: "it ran out of memory",
  sql_proxy_errors: "it could not reach its database"
};

// The marks our subject puts in front ("TEST (ignore): ", "URGENT "), kept in front of a group's own title.
function marks(i) {
  var body = ours(i) || "";
  var test = "";
  var urgent = "";
  var n;
  for (n = 0; n < 2; n++) {
    if (TEST_MARK.test(body)) { test = "TEST (ignore): "; body = body.replace(TEST_MARK, ""); }
    if (URGENT_MARK.test(body)) { urgent = "URGENT "; body = body.replace(URGENT_MARK, ""); }
  }
  return test + urgent;
}

// The group an event belongs to (above), or null: { key, what, action, detail, keepOpen }.
function group(i, h) {
  var metricType = text(field(i.metric, "type"));
  var labels = field(field(i, "resource"), "labels");
  var project = text(field(labels, "project_id")) || text(i.scoping_project_id);
  var severity = text(i.severity).toLowerCase() || "none";
  var started = Number(i.started_at);
  var name, slot, size, service, span, kind;
  if (metricType.indexOf(GROUP_PREFIX) !== 0 || !isFinite(started) || started <= 0 || !project) { return null; }
  name = metricType.substring(GROUP_PREFIX.length);
  if (contains(CHANGE_METRICS, name)) {
    size = CHANGE_SLOT_SECONDS;
    slot = started - (started % size);
    span = clock(slot) + DASH + clock(slot + size) + " UTC";
    return {
      key: "changes" + SEPARATOR + project + SEPARATOR + name + SEPARATOR + severity + SEPARATOR + slot,
      what: marks(i) + area(project) + " settings changed during " + span + " (" +
        changed(name, text(field(field(i.metric, "labels"), "operation"))) + ")",
      action: act(i, h, DEPLOY_ACTION),
      detail: "One incident for this kind of change (" + name + ") in this project at this severity during " + span +
        ": a deploy makes many. Later ones in the slot are in this alert's log and page nobody. Compare the slot " +
        "with the deploy notes (the NOTICE's START and DONE); if no deploy was running, read the project's Admin " +
        "Activity log for the whole slot before resolving.",
      keepOpen: false
    };
  }
  if (contains(SERVICE_METRICS, name)) {
    service = text(field(labels, "service_name"));
    kind = " service";
    if (!service) { service = text(field(labels, "job_name")); kind = " job"; }
    if (!service) { return null; }
    size = SERVICE_SLOT_SECONDS;
    slot = started - (started % size);
    span = clock(slot) + DASH + clock(slot + size) + " UTC";
    return {
      key: "service" + SEPARATOR + project + SEPARATOR + service + SEPARATOR + severity + SEPARATOR + slot,
      what: marks(i) + "The " + service + kind + " is failing during " + span + " (" + FAILING[name] + ")",
      action: act(i, h, ACT_TODAY),
      detail: "One incident for the " + service + kind + "'s start-up, crash, memory and database alerts at this " +
        "severity during " + span + ". Later ones in the slot are in this alert's log and page nobody. PagerDuty is " +
        "not told when one goes quiet: check each one's Cloud Monitoring incident before resolving it by hand.",
      keepOpen: true
    };
  }
  return null;
}

function main() {
  var i = incidentOf(PD.inputRequest.body);
  var h, best, key, event, grouped, closed;
  if (!i) {
    PD.fail("not a Cloud Monitoring notification: no incident object in the body");
    return;
  }
  h = heading(i);
  best = page(i);
  closed = text(i.state).toLowerCase() === "closed";
  grouped = group(i, h);
  if (grouped && grouped.keepOpen && closed) {
    // One member of a service's group closed: the incident stays open for a person (above).
    return;
  }
  key = text(i.incident_id);
  if (!key && (text(i.policy_name) || text(i.condition_name))) {
    key = text(i.policy_name) + " / " + text(i.condition_name);
  }
  event = {
    event_type: closed ? PD.Resolve : PD.Trigger,
    description: grouped ? titled(grouped.what, grouped.action) : titled(h.what, h.action),
    details: details(i, grouped ? { what: h.what, action: grouped.action } : h, best),
    client: "Watchtower: " + best.name,
    client_url: link(best.uid),
    contexts: contexts(i, best)
  };
  if (grouped) {
    event.details.grouped = grouped.detail;
    key = grouped.key;
  }
  if (key) { event.incident_key = key; }
  PD.emitGenericEvents([event]);
}

main();
