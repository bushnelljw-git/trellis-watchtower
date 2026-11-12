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
var TITLE_LIMIT = 250;

// Monitoring's tag in front of a subject: "[ALERT - Warning] ", "[RESOLVED] ". At most one is dropped.
var TAG = /^\[[^\]]*\] /;
// A subject of ours after the tag: tpa-platform's "<environment> \u00b7 <what happened>". Monitoring's own subject
// for a policy without one ("<condition> on <resource>") has no such shape and is not used.
var OUR_SUBJECT = /^[a-z][a-z-]* \u00b7 /;

// The watchtower's pages (cloud/dashboards: each is at <watchtower>/d/<uid>).
var OVERVIEW = { uid: "tw-cloud-overview", name: "overview" };
var SERVICE_UID = "tw-cloud-service-";
// The Cloud Run services that have a page of their own (cloud/dashboards/service-<name>.json).
var SERVICE_PAGES = [
  "auth", "auth-outbox-publisher", "connectors", "crm-web", "engine", "model-gateway", "records", "svc-ops",
  "svc-twilio-rest", "svc-voice", "tpa-api", "tpa-jobs-drains", "watchtower", "web"
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

function title(i) {
  var subject = text(field(i.documentation, "subject")).replace(TAG, "");
  var policy = text(i.policy_name);
  var condition = text(i.condition_name);
  var chosen = "Cloud Monitoring alert";
  if (OUR_SUBJECT.test(subject)) {
    chosen = plain(subject.replace(OUR_SUBJECT, ""));
  } else if (policy && condition) {
    chosen = policy + SEPARATOR + condition;
  } else if (text(i.summary)) {
    chosen = text(i.summary);
  }
  if (chosen.length > TITLE_LIMIT) { chosen = chosen.substring(0, TITLE_LIMIT - 3) + "..."; }
  return chosen;
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
function details(i, what, best) {
  var all = [
    ["what_happened", what],
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

function main() {
  var i = incidentOf(PD.inputRequest.body);
  var what, best, key, event;
  if (!i) {
    PD.fail("not a Cloud Monitoring notification: no incident object in the body");
    return;
  }
  what = title(i);
  best = page(i);
  key = text(i.incident_id);
  if (!key && (text(i.policy_name) || text(i.condition_name))) {
    key = text(i.policy_name) + " / " + text(i.condition_name);
  }
  event = {
    event_type: text(i.state).toLowerCase() === "closed" ? PD.Resolve : PD.Trigger,
    description: what,
    details: details(i, what, best),
    client: "Watchtower: " + best.name,
    client_url: link(best.uid),
    contexts: contexts(i, best)
  };
  if (key) { event.incident_key = key; }
  PD.emitGenericEvents([event]);
}

main();
