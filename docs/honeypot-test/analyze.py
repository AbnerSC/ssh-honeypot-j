#!/usr/bin/env python3
# Analyze attempts.jsonl -> stats.json + console summary
import json, collections, os
OUTDIR = os.path.dirname(os.path.abspath(__file__))
evs = [json.loads(l) for l in open(os.path.join(OUTDIR,"attempts.jsonl"),encoding="utf-8")]
total = len(evs)
by_proto = collections.Counter(e["proto"] for e in evs)
accepted = sum(1 for e in evs if e.get("accepted"))
opened = sum(1 for e in evs if e.get("opened"))
errors = collections.Counter(e.get("err") for e in evs if e.get("err"))
per_attacker = collections.defaultdict(lambda: collections.Counter())
for e in evs:
    per_attacker[e["attacker"]][e["proto"]] += 1
    per_attacker[e["attacker"]]["total"] += 1
users = collections.Counter(e["user"] for e in evs)
pwds = collections.Counter(e["pw"] for e in evs)
total_cmds = sum(e.get("n_cmds",0) for e in evs)
banners = collections.Counter(e.get("client_banner") for e in evs if e.get("client_banner"))
# timeline per minute
tl = collections.Counter()
for e in evs:
    m = int(e["ts"]//60)
    tl[m]+=1
timeline = [{"minute":k,"attempts":tl[k]} for k in sorted(tl)]
stats = {
    "total": total, "by_proto": dict(by_proto),
    "accepted": accepted, "accepted_rate": round(accepted/total*100,2),
    "opened": opened, "errors": dict(errors),
    "per_attacker": {k:dict(v) for k,v in sorted(per_attacker.items())},
    "distinct_users": len(users), "top_users": users.most_common(10),
    "distinct_pwds": len(pwds), "top_pwds": pwds.most_common(10),
    "total_cmds": total_cmds, "distinct_client_banners": len(banners),
    "client_banners": dict(banners), "timeline": timeline,
    "sample": evs[:8],
}
json.dump(stats, open(os.path.join(OUTDIR,"stats.json"),"w",encoding="utf-8"),
          ensure_ascii=False, indent=2)
print("total:",total,"by_proto:",dict(by_proto))
print("accepted:",accepted,f"({stats['accepted_rate']}%)  opened_shell:",opened)
print("distinct users:",len(users)," distinct pwds:",len(pwds)," total_cmds:",total_cmds)
print("errors:",dict(errors) or "NONE")
print("minutes covered:",len(timeline)," first/last:",timeline[0],timeline[-1])
print("per_attacker totals:",{k:v['total'] for k,v in sorted(per_attacker.items())})
