"""Runs the OpenID Foundation OID4VP 1.0 Final + HAIP verifier test plan against a local eudiw-adapter.

See README.md in this directory. Synthetic keys only.
"""
import json, ssl, subprocess, sys, time, base64, urllib.request, urllib.parse
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

config = json.load(open("suite-config.json"))
variant = json.dumps({"credential_format": "sd_jwt_vc", "response_mode": "direct_post.jwt"})
status, body = http("POST", f"{SUITE}/api/plan?planName=oid4vp-1final-verifier-haip-test-plan&variant="
                    + urllib.parse.quote(variant), config, ctx=CTX)
plan = json.loads(body)
plan_id = plan["id"]
print("plan", plan_id)
modules = [m["testModule"] for m in plan["modules"]]
VERBOSE = "-v" in sys.argv
only = [a for a in sys.argv[1:] if a != "-v"] or modules
results = []
for module in modules:
    if module not in only:
        continue
    status, body = http("POST", f"{SUITE}/api/runner?test={module}&plan={plan_id}", b"", {"Content-Type": "application/json"}, ctx=CTX)
    test_id = json.loads(body)["id"]
    endpoint = None
    for _ in range(60):
        info = json.loads(http("GET", f"{SUITE}/api/runner/{test_id}", ctx=CTX)[1])
        endpoint = (info.get("exposed") or {}).get("authorization_endpoint")
        if endpoint and info.get("status") in ("WAITING", "CONFIGURED"):
            break
        time.sleep(1)
    tok = token()
    st, sess = http("POST", f"{ADAPTER}/v1/verification-sessions",
                    {"policy_id": "pid", "mode": "same_device"},
                    {"Authorization": "Bearer " + tok, "Idempotency-Key": test_id}, ctx=CTX)
    session = json.loads(sess)
    query = session["wallet_launch"]["launch_uri"].split("?", 1)[1]
    st2, _ = http("GET", endpoint + "?" + query, ctx=CTX)
    final = None
    for _ in range(60):
        info = json.loads(http("GET", f"{SUITE}/api/info/{test_id}", ctx=CTX)[1])
        if info.get("status") in ("FINISHED", "INTERRUPTED") or (info.get("status") == "WAITING" and _ > 5):
            final = info
            break
        time.sleep(1)
    adapter = json.loads(http("GET", f"{ADAPTER}/v1/verification-sessions/{session['id']}",
                              headers={"Authorization": "Bearer " + tok}, ctx=CTX)[1])
    row = (module, final.get("status"), final.get("result"), adapter.get("status"), adapter.get("reason"))
    results.append(row)
    print("%-60s suite=%s/%s adapter=%s %s" % row, test_id, flush=True)
    if "-v" in sys.argv[0:1] or VERBOSE:
        log = json.loads(http("GET", f"{SUITE}/api/log/{test_id}", ctx=CTX)[1])
        for e in log:
            if e.get("result") in ("FAILURE", "WARNING", "REVIEW"):
                print("   ", e.get("result"), e.get("src"), (e.get("msg") or "")[:300])
json.dump({"plan": plan_id, "results": results}, open("results.json", "w"), indent=1)
