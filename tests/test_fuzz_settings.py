"""Shake the whole settings registry: random (but valid) values for every setting, random link shapes, random
visitors. Whatever the combination, the server must answer with a sane status and never crash or leak the
password hash / API keys / webhook URL."""
import random
import string

from tests.test_server import NOW, V, client, run
from zinc.models import GeoRule, LinkSpec, RouteRule, validate_spec
from zinc.options import OPTIONS, Settings
from zinc.secret import hash_password
from zinc.server import make_app
from zinc.store import Store

SANE = {200, 302, 303, 307, 400, 401, 404, 410, 429, 503}
UAS = ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari", "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
       "Slackbot-LinkExpanding 1.0", "curl/8.0", "", "Mozilla/5.0 (Linux; Android 14) Mobile",
       "😀" * 40 + " odd/ua"]
LANGS = ["", "zh-TW,zh;q=0.9,en;q=0.8", "en-US", "ja", "*", "xx-YY;q=abc", "zh-Hant-TW;q=0.5, fr;q=0.9", ",,,;q=;"]
COUNTRIES = [None, "TW", "JP", "US", "DE", "XX", "T1", "BR"]
TARGETS = ["https://a.example/", "https://b.example/path?x=1", "https://c.example/#frag", "https://dé.example/ü?q=日本"]
SECRET_VALUES = ["sk-test-key-123", "https://hooks.example/secret-path"]


def random_value(o, rng):
    k = o.kind
    if k == "bool":
        return rng.choice([True, False])
    if k in ("int", "float"):
        lo = o.min if o.min is not None else min(0, o.default)
        hi = o.max if o.max is not None else max(10, o.default * 2 or 10)
        hi = min(hi, lo + 100_000)
        v = rng.choice([lo, hi, o.default, rng.uniform(lo, hi)])
        return int(v) if k == "int" else float(v)
    if k == "choice":
        return rng.choice(o.choices)
    if k == "color":
        return rng.choice(["", "#0f766e", "#abc", "#FFFFFF"])
    if k == "list" and o.choices:
        picks = [c for c in o.choices if rng.random() < 0.5]
        return picks if o.key != "rule_order" else rng.sample(list(o.choices), len(o.choices))
    if k == "str":
        return rng.choice([o.default, "", "短い text", "".join(rng.choices(string.printable[:62], k=rng.randint(0, 30)))])
    return o.default                                          # regex, map, secret, url, free lists: keep the default


def random_settings(rng):
    s = Settings()
    for o in OPTIONS.values():
        if rng.random() < 0.5:
            try:
                s.apply({o.key: random_value(o, rng)})
            except ValueError:
                pass                                          # an invalid combination is allowed to be refused, never to crash
    s.apply({"vt_key": SECRET_VALUES[0], "webhook_url": ""})
    return s


def random_spec(rng, clock_now):
    mode = rng.choice(["plain", "note", "count", "box", "door"])
    variants = [V(chr(65 + i), rng.choice(TARGETS), rng.choice([1, 1, 3])) for i in range(rng.randint(1, 4))]
    if mode == "door" and rng.random() < 0.5:
        variants.append(V("trap", ""))
    kw = {}
    if rng.random() < 0.4:
        kw["geo_rules"] = [GeoRule(rng.choice(["asia", "TW", "europe", "JP"]), [V("G", rng.choice(TARGETS))])]
    if rng.random() < 0.4:
        kw["route_rules"] = [RouteRule(rng.choice(["lang", "device"]), "ja" if rng.random() < .5 else "ios",
                                       [V("R", rng.choice(TARGETS))])]
        if kw["route_rules"][0].kind == "device":
            kw["route_rules"][0] = RouteRule("device", rng.choice(["ios", "android", "mobile", "desktop"]),
                                             kw["route_rules"][0].variants)
    if rng.random() < 0.3:
        kw["pw_hash"] = hash_password("pw", iterations=1000)
    if rng.random() < 0.3:
        kw["max_passes"] = rng.randint(1, 3)
    if rng.random() < 0.2:
        kw["starts_at"] = clock_now + rng.choice([-10, 30])
    if rng.random() < 0.3:
        kw["label"] = rng.choice(["promo", "週報 📎", "<b>x</b>"])
    return LinkSpec(mode=mode, variants=variants, message="hello <i>there</i>" if mode == "note" else "",
                    auto_locale=rng.random() < 0.5, **kw)


def one_round(seed):
    rng = random.Random(seed)
    settings = random_settings(rng)
    for _ in range(50):                                       # the form would refuse invalid shapes (e.g. a 1-door "door"): skip them
        spec = random_spec(rng, NOW)
        try:
            validate_spec(spec)
            break
        except ValueError:
            continue
    else:
        raise AssertionError("could not generate a valid spec")
    store = Store()
    link = store.create_link(spec, ttl_s=rng.choice([600, 10**6]), max_opens=rng.choice([None, 2]), now=NOW,
                             token_length=settings.token_length)
    store.set_status(link.id, "live")
    app = make_app(store, link.id, settings=settings, clock=lambda: NOW + rng.choice([0, 0, 5000]))
    path = f"/{link.token}"
    bodies, statuses = [], []

    async def go():
        async with client(app) as c:
            for _ in range(rng.randint(8, 14)):
                headers = {"CF-Connecting-IP": f"9.9.{rng.randint(0, 3)}.{rng.randint(1, 3)}",
                           "User-Agent": rng.choice(UAS), "Accept-Language": rng.choice(LANGS)}
                if (cc := rng.choice(COUNTRIES)):
                    headers["CF-IPCountry"] = cc
                kind = rng.choice(["entry", "entry", "go", "unlock", "junk", "door"])
                if kind == "unlock":
                    r = await c.post(f"{path}/unlock", json={"p": rng.choice(["pw", "no", 5])}, headers=headers)
                elif kind == "go":
                    r = await c.get(f"{path}/go", headers=headers, allow_redirects=False)
                elif kind == "door":
                    r = await c.get(f"{path}/go?d={rng.choice(['0', '1', '9', 'x', '-1', ''])}", headers=headers,
                                    allow_redirects=False)
                elif kind == "junk":
                    r = await c.request(rng.choice(["GET", "POST", "PUT", "HEAD", "DELETE"]),
                                        rng.choice(["/", "/x/y/z", f"{path}/extra", path + "/%00", "/..%2f"]),
                                        headers=headers, allow_redirects=False)
                else:
                    r = await c.get(path, headers=headers, allow_redirects=False)
                assert r.status in SANE, (seed, kind, r.status)
                statuses.append(r.status)
                bodies.append(await r.text() + " ".join(f"{k}:{v}" for k, v in r.headers.items()))
    run(go())
    blob = "\n".join(bodies)
    assert not spec.pw_hash or spec.pw_hash not in blob, seed
    assert SECRET_VALUES[0] not in blob, seed
    return statuses


def test_hundreds_of_random_setting_and_link_combinations_never_crash_or_leak():
    seen = set()
    for seed in range(250):
        seen.update(one_round(seed))
    assert {200, 302, 400, 401, 404, 410, 503} <= seen, seen        # the run really visited every kind of answer


def test_the_random_generator_really_explores_the_registry():
    """Guard against a vacuous fuzz: across the seeds most settings must take more than one value."""
    seen = {k: set() for k in OPTIONS}
    for seed in range(60):
        rng = random.Random(seed)
        s = random_settings(rng)
        for k in OPTIONS:
            seen[k].add(repr(getattr(s, k)))
    still = [k for k, v in seen.items() if len(v) < 2 and OPTIONS[k].kind in ("bool", "int", "float", "choice")]
    assert still == []
