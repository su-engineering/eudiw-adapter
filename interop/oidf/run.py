"""Runs the OpenID Foundation OID4VP 1.0 Final + HAIP verifier test plan against a local eudiw-adapter.

See README.md in this directory. Synthetic keys only.
"""
import json, os, ssl, subprocess, sys, time, base64, urllib.request, urllib.parse
SUITE = "https://localhost.emobix.co.uk:8443"
ADAPTER = "https://localhost:8453"
CTX = ssl._create_unverified_context()  # local suite with its own development certificate

def http(method, url, body=None, headers=None, ctx=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if body is not None and not isinstance(body, bytes):
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def token():
    now = int(time.time())
    h = b64u(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    c = b64u(json.dumps({"iss": "https://oidf.local", "aud": "eudiw-adapter", "azp": "oidf-portal",
                         "scope": "verification:create verification:read", "iat": now, "exp": now + 600}).encode())
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", "token-key.pem"], input=f"{h}.{c}".encode(),
                         capture_output=True).stdout
    return f"{h}.{c}.{b64u(sig)}"

USAGE = "run.py [-v] [--check expected.json] [--logs DIR] [module ...]"
args = sys.argv[1:]
VERBOSE = "-v" in args
def option(name):
    if name not in args:
        return None
    i = args.index(name)
    if i + 1 >= len(args):
        sys.exit(USAGE)
    value = args[i + 1]
    del args[i:i + 2]
    return value
CHECK = option("--check")
LOGS = option("--logs")
only = [a for a in args if a != "-v"]
if CHECK and only:
    sys.exit("--check runs the whole plan; drop the module names")

config = json.load(open("suite-config.json"))
variant = json.dumps({"credential_format": "sd_jwt_vc", "response_mode": "direct_post.jwt"})
status, body = http("POST", f"{SUITE}/api/plan?planName=oid4vp-1final-verifier-haip-test-plan&variant="
                    + urllib.parse.quote(variant), config, ctx=CTX)
plan = json.loads(body)
plan_id = plan["id"]
print("plan", plan_id)
modules = [m["testModule"] for m in plan["modules"]]
only = only or modules
results = []
logs = {}
for module in modules:
    if module not in only:
        continue
    status, body = http("POST", f"{SUITE}/api/runner?test={module}&plan={plan_id}", b"", {"Content-Type": "application/json"}, ctx=CTX)
    test_id = json.loads(body)["id"]
    endpoint = None
    for _ in range(60):
        runner = json.loads(http("GET", f"{SUITE}/api/runner/{test_id}", ctx=CTX)[1])
        endpoint = (runner.get("exposed") or {}).get("authorization_endpoint")
        state = json.loads(http("GET", f"{SUITE}/api/info/{test_id}", ctx=CTX)[1]).get("status")
        if endpoint and state in ("WAITING", "CONFIGURED"):
            break
        time.sleep(1)
    else:
        sys.exit(f"{module}: the suite did not expose its authorization endpoint")
    tok = token()
    st, sess = http("POST", f"{ADAPTER}/v1/verification-sessions",
                    {"policy_id": "pid", "mode": "same_device"},
                    {"Authorization": "Bearer " + tok, "Idempotency-Key": test_id}, ctx=CTX)
    if st not in (200, 201):
        sys.exit(f"creating a session failed: HTTP {st} {sess[:500]}")
    session = json.loads(sess)
    query = session["wallet_launch"]["launch_uri"].split("?", 1)[1]
    st2, _ = http("GET", endpoint + "?" + query, ctx=CTX)
    # A module ends either FINISHED or WAITING at its REVIEW step, where the suite asks for a screenshot of the
    # verifier's result page. A headless service has none, so the run stops there.
    final = {}
    for i in range(90):
        info = json.loads(http("GET", f"{SUITE}/api/info/{test_id}", ctx=CTX)[1])
        if info.get("status") in ("FINISHED", "INTERRUPTED"):
            final = info
            break
        if info.get("status") == "WAITING" and i > 3:
            entries = json.loads(http("GET", f"{SUITE}/api/log/{test_id}", ctx=CTX)[1])
            if any(e.get("result") == "REVIEW" for e in entries):
                final = info
                break
        time.sleep(1)
    adapter = json.loads(http("GET", f"{ADAPTER}/v1/verification-sessions/{session['id']}",
                              headers={"Authorization": "Bearer " + tok}, ctx=CTX)[1])
    log = json.loads(http("GET", f"{SUITE}/api/log/{test_id}", ctx=CTX)[1])
    logs[module] = log
    problems = [e for e in log if e.get("result") in ("FAILURE", "WARNING")]
    reached_review = any(e.get("result") == "REVIEW" for e in log)
    suite_result = final.get("result") or ("REVIEW" if reached_review else None)
    row = (module, final.get("status"), suite_result, adapter.get("status"), adapter.get("reason"), len(problems))
    results.append(row)
    print("%-60s suite=%s/%s adapter=%s %s failures+warnings=%d" % row, test_id, flush=True)
    if VERBOSE:
        for e in log:
            if e.get("result") in ("FAILURE", "WARNING", "REVIEW"):
                print("   ", e.get("result"), e.get("src"), (e.get("msg") or "")[:300])
json.dump({"plan": plan_id, "results": results}, open("results.json", "w"), indent=1)
if LOGS:
    os.makedirs(LOGS, exist_ok=True)
    json.dump({"plan": plan_id, "results": results}, open(os.path.join(LOGS, "results.json"), "w"), indent=1)
    for module, log in logs.items():
        json.dump(log, open(os.path.join(LOGS, module + ".json"), "w"), indent=1)

if CHECK:
    expected = json.load(open(CHECK))
    errors = []
    ran = {r[0] for r in results}
    for missing in sorted(set(expected) - ran):
        errors.append(f"{missing}: expected but the plan did not run it")
    for extra in sorted(ran - set(expected)):
        errors.append(f"{extra}: ran but has no expected outcome")
    for module, suite_status, suite_result, a_status, a_reason, problems in results:
        if module not in expected:
            continue
        want_status, want_reason = expected[module]
        if (a_status, a_reason) != (want_status, want_reason):
            errors.append(f"{module}: adapter {a_status} {a_reason}, expected {want_status} {want_reason}")
        if problems:
            errors.append(f"{module}: {problems} failures or warnings in the suite log")
        if suite_status not in ("WAITING", "FINISHED") or suite_result not in ("REVIEW", "PASSED"):
            errors.append(f"{module}: suite result {suite_status}/{suite_result}")
    if errors:
        print("\nFAILED")
        for e in errors:
            print("  " + e)
        sys.exit(1)
    print(f"\nOK: {len(results)} modules ended as expected, no failures or warnings in the suite log")
