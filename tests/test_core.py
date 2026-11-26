import sqlite3
from collections import Counter

import pytest

from zinc import geo
from zinc.geo import (CONTINENTS, Geo, client_ip, continent_of, header_resolver, is_valid_match,
                      resolve_geo)
from zinc.lifecycle import effective_state
from zinc.models import GeoRule, LinkSpec, Variant, validate_spec
from zinc.resolver import pick_sticky, select_group, visitor_id
from zinc.store import Store
from zinc.view import (bars, build_from_form, fmt_remaining, parse_geo, parse_targets, spark, state_label)

A, B = "https://a.example/", "https://b.example/"


def V(n, u, w=1):
    return Variant(n, u, w)


# ---- geo -------------------------------------------------------------------------------------
@pytest.mark.parametrize("cc,cont", [("TW", "asia"), ("JP", "asia"), ("DE", "europe"), ("GB", "europe"),
                                     ("US", "north_america"), ("BR", "south_america"), ("ZA", "africa"),
                                     ("AU", "oceania"), ("AQ", "antarctica"), ("tw", "asia")])
def test_continent_table(cc, cont):
    assert continent_of(cc) == cont


def test_every_country_belongs_to_exactly_one_continent():
    total = sum(len(codes.split()) for codes in geo._CONTINENT_CODES.values())
    assert total == len(geo.COUNTRY_TO_CONTINENT)


def test_continent_and_country_namespaces_never_collide():
    # ISO codes AS/AF/NA/SA are countries (American Samoa, Afghanistan, Namibia, Saudi Arabia)
    assert continent_of("AS") == "oceania" and continent_of("AF") == "asia"
    assert continent_of("NA") == "africa" and continent_of("SA") == "asia"
    assert all(is_valid_match(c) for c in ("AS", "AF", "NA", "SA", "asia", "north_america"))
    assert not any(is_valid_match(x) for x in ("ASIA", "Asia", "EU", "europe ", "ZZ", "", "tw"))
    assert set(CONTINENTS) == {"asia", "europe", "north_america", "south_america", "africa", "oceania", "antarctica"}


@pytest.mark.parametrize("raw,want", [("tw", "TW"), (" JP ", "JP"), ("XX", None), ("T1", None), ("", None),
                                      ("ABC", None), ("1A", None), ("t1", None)])
def test_header_resolver(raw, want):
    assert header_resolver({"CF-IPCountry": raw}, "1.1.1.1") == want


def test_resolver_chain_falls_through_and_names_its_source():
    def second(headers, ip):
        return "FR"
    g = resolve_geo({"CF-IPCountry": "XX"}, "1.1.1.1", (header_resolver, second))
    assert (g.country, g.continent, g.source) == ("FR", "europe", "second")
    assert resolve_geo({"CF-IPCountry": "TW"}, "1.1.1.1", (header_resolver, second)).source == "header_resolver"
    assert resolve_geo({}, "1.1.1.1") == Geo()


def test_client_ip_precedence():
    assert client_ip({"CF-Connecting-IP": "1.1.1.1", "X-Forwarded-For": "2.2.2.2"}, "9.9.9.9") == "1.1.1.1"
    assert client_ip({"X-Forwarded-For": "2.2.2.2, 3.3.3.3"}, "9.9.9.9") == "2.2.2.2"
    assert client_ip({}, "9.9.9.9") == "9.9.9.9"


# ---- resolver --------------------------------------------------------------------------------
def spec3():
    return LinkSpec(mode="plain", variants=[V("D", "https://d.example/")], geo_rules=[
        GeoRule("asia", [V("AS", "https://as.example/")]), GeoRule("TW", [V("TW", "https://tw.example/")])])


def test_group_selection_precedence():
    s = spec3()
    pick = lambda c: select_group(s, resolve_geo({"CF-IPCountry": c}, ""))[0]  # noqa: E731
    assert (pick("TW"), pick("JP"), pick("DE"), pick("XX")) == ("TW", "asia", "default", "default")
    only_continent = LinkSpec(mode="plain", variants=[V("D", A)], geo_rules=[GeoRule("europe", [V("E", B)])])
    assert select_group(only_continent, Geo("DE", "europe"))[0] == "europe"
    assert select_group(only_continent, Geo("TW", "asia"))[0] == "default"


def test_sticky_pick_is_deterministic_weighted_and_salt_dependent():
    vs = [V("A", A, 1), V("B", B, 3)]
    assert pick_sticky(vs, "v1", "s") == pick_sticky(vs, "v1", "s")
    counts = Counter(pick_sticky(vs, f"v{i}", "s").name for i in range(4000))
    assert 0.70 < counts["B"] / 4000 < 0.80
    flips = sum(pick_sticky(vs, f"v{i}", "s1").name != pick_sticky(vs, f"v{i}", "s2").name for i in range(1000))
    assert flips > 100                                           # links are independent experiments
    assert pick_sticky([V("only", A)], "x", "s").name == "only"


def test_visitor_id_is_salted_stable_and_hides_the_ip():
    a = visitor_id("salt1", "203.0.113.7", "UA")
    assert a == visitor_id("salt1", "203.0.113.7", "UA") and len(a) == 16
    assert len({a, visitor_id("salt2", "203.0.113.7", "UA"), visitor_id("salt1", "203.0.113.8", "UA"),
                visitor_id("salt1", "203.0.113.7", "UA2")}) == 4
    assert "203.0.113.7" not in a


# ---- models ----------------------------------------------------------------------------------
@pytest.mark.parametrize("spec,needle", [
    (LinkSpec(mode="zzz", variants=[V("A", A)]), "unknown mode"),
    (LinkSpec(mode="note", variants=[V("A", A)]), "message"),
    (LinkSpec(mode="plain", variants=[]), "default target"),
    (LinkSpec(mode="plain", variants=[V("A", A)], geo_rules=[GeoRule("Asia", [V("A", A)])]), "bad geo match"),
    (LinkSpec(mode="plain", variants=[V("A", A)], geo_rules=[GeoRule("ZZ", [V("A", A)])]), "bad geo match"),
    (LinkSpec(mode="plain", variants=[V("A", A)], geo_rules=[GeoRule("TW", [V("A", A)]), GeoRule("TW", [V("B", B)])]), "duplicate"),
    (LinkSpec(mode="plain", variants=[V("A", A, 0)]), "weight"),
    (LinkSpec(mode="plain", variants=[V("A", "ftp://x.example")]), "http"),
    (LinkSpec(mode="plain", variants=[V("A", "javascript:alert(1)")]), "http"),
    (LinkSpec(mode="plain", variants=[V("A", A), V("T", "")]), "trap door"),
    (LinkSpec(mode="door", variants=[V("A", A)]), "at least 2"),
    (LinkSpec(mode="door", variants=[V("T", ""), V("U", "")]), "all trap"),
    (LinkSpec(mode="box", variants=[V(str(i), A) for i in range(7)]), "variants"),
    (LinkSpec(mode="door", variants=[V("A", A), V("B", B)], geo_rules=[GeoRule("TW", [V("A", A)])]), "at least 2"),
])
def test_validate_spec_rejects(spec, needle):
    with pytest.raises(ValueError, match=needle):
        validate_spec(spec)


def test_valid_specs_pass_and_roundtrip():
    s = LinkSpec(mode="door", variants=[V("A", A), V("B", B), V("T", "")], auto_locale=True, message="x",
                 geo_rules=[GeoRule("asia", [V("A", A), V("T", "")])])
    validate_spec(s)
    assert LinkSpec.from_json(s.to_json()) == s


# ---- store -----------------------------------------------------------------------------------
def mk(store=None, **kw):
    store = store or Store()
    return store, store.create_link(LinkSpec(mode="plain", variants=[V("A", A)]), now=1000.0, **kw)


def test_links_get_unique_ids_and_12_char_tokens_and_validate():
    s, l1 = mk()
    _, l2 = mk(s)
    assert l1.id != l2.id and l1.token != l2.token and len(l1.token) == 12 and l1.status == "starting"
    with pytest.raises(ValueError):
        s.create_link(LinkSpec(mode="plain", variants=[]))
    with pytest.raises(ValueError):
        s.set_status(l1.id, "bogus")


def test_stats_unique_vs_total_and_funnel():
    s, l = mk()
    for vid in ("a", "a", "b"):
        s.add_hit(l.id, "open", vid, "TW", "asia")
    s.add_hit(l.id, "pass", "a", "TW", "asia", variant="A")
    s.add_hit(l.id, "bot", "bot1")
    st = s.stats(l.id)
    assert (st["opens"], st["uniques"], st["passes"], st["pass_uniques"], st["bots"]) == (3, 2, 1, 1, 1)
    assert st["by_country"] == {"TW": 2} and st["by_variant"] == {"A": 1}
    with pytest.raises(ValueError):
        s.add_hit(l.id, "weird", "x")


def test_sparkline_buckets_by_minute_and_drops_old_hits():
    s, l = mk()
    now = 10_000.0
    for age in (5, 59, 61, 600, 1199, 1300):
        s.add_hit(l.id, "open", f"v{age}", now=now - age)
    sp = s.stats(l.id, now)["spark"]
    assert len(sp) == 20 and sp[-1] == 2 and sp[-2] == 1 and sp[-11] == 1 and sp[0] == 1 and sum(sp) == 5


def test_visitor_rank_is_first_seen_order():
    s, l = mk()
    for vid in ("x", "y", "x", "z"):
        s.add_hit(l.id, "open", vid)
    assert [s.visitor_rank(l.id, v) for v in ("x", "y", "z", "new")] == [1, 2, 3, 4]
    assert s.has_hit(l.id, "x", "open") and not s.has_hit(l.id, "x", "pass")
    assert s.last_open_ts(l.id) is not None and s.count_opens(l.id) == 4


def test_extend_adds_to_future_expiry_but_restarts_from_now_when_expired():
    s, l = mk(ttl_s=100)                                   # expires at 1100
    s.extend(l.id, 50, now=1000.0)
    assert s.get_link(l.id).expires_at == 1150.0
    s.extend(l.id, 50, now=5000.0)                         # long expired: do not add to the past
    assert s.get_link(l.id).expires_at == 5050.0
    with pytest.raises(KeyError):
        s.extend("nope", 1)


def test_old_database_without_verdict_column_is_migrated(tmp_path):
    path = str(tmp_path / "old.db")
    db = sqlite3.connect(path)
    db.executescript("""CREATE TABLE links(id TEXT PRIMARY KEY, token TEXT NOT NULL, spec TEXT NOT NULL, status TEXT NOT NULL,
      created_at REAL NOT NULL, expires_at REAL, max_opens INTEGER, hostname TEXT, port INTEGER, salt TEXT NOT NULL,
      scan TEXT, grace_until REAL);""")
    db.commit()
    db.close()
    s = Store(path)
    link = s.create_link(LinkSpec(mode="plain", variants=[V("A", A)]))
    s.set_verdict(link.id, "{}")
    assert s.get_link(link.id).verdict == "{}"


# ---- lifecycle -------------------------------------------------------------------------------
@pytest.mark.parametrize("status,expires,max_opens,opens,admitted,now,want", [
    ("live", 2000, None, 0, False, 1500, "live"),
    ("live", 2000, None, 0, False, 2000, "dead"),          # expiry is inclusive
    ("soft_dead", None, None, 0, False, 1, "dead"), ("dead", None, None, 0, False, 1, "dead"),
    ("failed", None, None, 0, False, 1, "dead"), ("paused", None, None, 0, False, 1, "paused"),
    ("live", None, 3, 3, False, 1, "dead"), ("live", None, 3, 2, False, 1, "live"),
    ("live", None, 3, 3, True, 1, "live"),                 # admitted visitors may finish a full link
    ("starting", None, None, 0, False, 1, "live"),
])
def test_effective_state(status, expires, max_opens, opens, admitted, now, want):
    s, l = mk(max_opens=max_opens)
    link = s.get_link(l.id)
    link.status, link.expires_at = status, expires
    assert effective_state(link, now, opens, admitted) == want


# ---- view helpers ----------------------------------------------------------------------------
def test_spark_scales_and_keeps_small_values_visible():
    assert spark([0, 0, 0]) == "▁▁▁" and spark([]) == ""
    assert spark([0, 1, 100])[0] == "▁" and spark([0, 1, 100])[1] != "▁" and spark([0, 1, 100])[2] == "█"
    assert spark([4, 8]) == "▅█"


def test_bars_are_proportional_sorted_and_fold_the_tail():
    out = bars({"TW": 10, "JP": 5, "DE": 1}, width=10)
    assert out == ["TW ██████████ 10", "JP █████ 5", "DE █ 1"]
    folded = bars({c: n for c, n in zip("ABCDEFG", range(7, 0, -1))}, top=3)
    assert folded[-1].startswith("other") and folded[-1].endswith(" 10") and len(folded) == 4
    assert bars({}) == []


@pytest.mark.parametrize("sec,want", [(None, "∞"), (0, "00:00"), (-5, "00:00"), (65, "01:05"), (3599, "59:59"), (3600, "1h00m"), (7385, "2h03m")])
def test_fmt_remaining(sec, want):
    assert fmt_remaining(sec) == want


def test_state_labels():
    s, l = mk(ttl_s=100, max_opens=1)
    link = s.get_link(l.id)
    link.status = "live"
    assert state_label(link, 1050, 0) == "● 運作"
    assert state_label(link, 1200, 0) == "◐ 軟死"
    assert state_label(link, 1050, 1) == "◍ 額滿"
    for status, want in (("paused", "⏸ 暫停"), ("dead", "✝ 死亡"), ("failed", "✗ 失敗"), ("starting", "… 啟動"), ("soft_dead", "◐ 軟死")):
        link.status = status
        assert state_label(link, 1050, 0) == want


def test_form_syntax_and_errors():
    vs = parse_targets("https://a.example https://b.example*3 !")
    assert [(v.name, v.url, v.weight) for v in vs] == [("A", "https://a.example", 1), ("B", "https://b.example", 3), ("C", "", 1)]
    assert parse_targets("https://x.example/?a=b*c")[0].weight == 1       # '*' inside a URL is not a weight
    rules = parse_geo("asia=https://a.example https://b.example; TW=https://tw.example")
    assert [(r.match, len(r.variants)) for r in rules] == [("asia", 2), ("TW", 1)]
    with pytest.raises(ValueError, match="缺少網址"):
        parse_geo("asia=")
    ok = build_from_form(mode="note", targets="https://a.example", message=" hi ", ttl_min="1.5", max_opens="7")
    assert ok[0].message == "hi" and ok[1] == 90.0 and ok[2] == 7
    assert build_from_form(mode="plain", targets="https://a.example")[1:] == (None, None)
    for kw, needle in (({"targets": ""}, "至少"), ({"targets": "https://a.example", "ttl_min": "abc"}, "數字"),
                       ({"targets": "https://a.example", "ttl_min": "0"}, "大於 0"),
                       ({"targets": "https://a.example", "max_opens": "0"}, "正整數"),
                       ({"targets": "https://a.example", "max_opens": "x"}, "正整數"),
                       ({"targets": "https://a.example", "geo": "Mars=https://b.example"}, "bad geo")):
        with pytest.raises(ValueError, match=needle):
            build_from_form(mode="plain", **kw)
