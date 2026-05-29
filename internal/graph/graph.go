// Package graph is Amankan's Graph Analysis Engine. It projects assets and their
// vulnerabilities into Neo4j and computes attack paths: chains of reachable
// assets, each compromisable via an exploitable vulnerability, that lead from an
// internet-exposed entry point to a business-critical "crown jewel" asset. This
// is the lateral-movement / attack-path differentiator of the design.
package graph

import (
	"context"
	"fmt"
	"sort"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/amankan/amankan/internal/models"
)

type Graph struct {
	driver neo4j.DriverWithContext
}

// Connect opens a Neo4j driver and verifies connectivity. Returns an error if
// the database is unreachable so callers can degrade gracefully (graph optional).
func Connect(ctx context.Context, uri, user, pass string) (*Graph, error) {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		return nil, fmt.Errorf("new driver: %w", err)
	}
	if err := driver.VerifyConnectivity(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("verify connectivity: %w", err)
	}
	g := &Graph{driver: driver}
	if err := g.ensureConstraints(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, err
	}
	return g, nil
}

func (g *Graph) Close(ctx context.Context) error { return g.driver.Close(ctx) }

func (g *Graph) ensureConstraints(ctx context.Context) error {
	stmts := []string{
		"CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
		"CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
		"CREATE CONSTRAINT account_id IF NOT EXISTS FOR (acc:Account) REQUIRE acc.id IS UNIQUE",
	}
	for _, s := range stmts {
		if err := g.write(ctx, s, nil); err != nil {
			return err
		}
	}
	return nil
}

// Exposure derives an asset's network exposure from its tags. Assets tagged
// "public" or "external" are treated as internet-facing entry points.
func Exposure(a models.Asset) string {
	for _, t := range a.Tags {
		if t == "public" || t == "external" || t == "internet" {
			return "external"
		}
	}
	return "internal"
}

// SyncAsset upserts an asset node.
func (g *Graph) SyncAsset(ctx context.Context, a models.Asset) error {
	return g.write(ctx,
		`MERGE (n:Asset {id:$id})
		 SET n.name=$name, n.target=$target, n.criticality=$crit, n.exposure=$exposure`,
		map[string]any{
			"id": a.ID, "name": a.Name, "target": a.Target,
			"crit": string(a.Criticality), "exposure": Exposure(a),
		})
}

// SyncFinding upserts a vulnerability node and links it to its asset.
func (g *Graph) SyncFinding(ctx context.Context, f models.Finding) error {
	return g.write(ctx,
		`MATCH (a:Asset {id:$assetId})
		 MERGE (v:Vulnerability {id:$id})
		 SET v.title=$title, v.cwe=$cwe, v.cvss=$cvss, v.risk=$risk, v.kev=$kev, v.severity=$sev
		 MERGE (a)-[:HAS_VULN]->(v)`,
		map[string]any{
			"assetId": f.AssetID, "id": f.ID, "title": f.Title, "cwe": f.CWE,
			"cvss": f.CVSS, "risk": f.RiskScore, "kev": f.KnownExploit, "sev": string(f.Severity),
		})
}

// UpsertReachability records that source asset can reach destination over the
// network (a candidate lateral-movement edge).
func (g *Graph) UpsertReachability(ctx context.Context, srcID, dstID string, port int, proto string) error {
	return g.write(ctx,
		`MATCH (s:Asset {id:$src}), (d:Asset {id:$dst})
		 MERGE (s)-[r:CAN_REACH]->(d)
		 SET r.port=$port, r.proto=$proto`,
		map[string]any{"src": srcID, "dst": dstID, "port": port, "proto": proto})
}

// ---- accounts / privilege escalation ----

// Account is a graph-only principal living on an asset at some privilege level.
// Privilege escalation and credential reuse between accounts are modeled as
// weighted edges so attack paths capture *how an attacker gains privilege*, not
// just which hosts are network-reachable.
type Account struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Privilege string `json:"privilege"` // user | service | admin | root | domain_admin
	AssetID   string `json:"asset_id"`
}

// SyncAccount upserts an account node and links it to its asset.
func (g *Graph) SyncAccount(ctx context.Context, a Account) error {
	return g.write(ctx,
		`MATCH (asset:Asset {id:$assetId})
		 MERGE (acc:Account {id:$id})
		 SET acc.username=$username, acc.privilege=$privilege, acc.asset_id=$assetId
		 MERGE (asset)-[:HAS_ACCOUNT]->(acc)`,
		map[string]any{"id": a.ID, "username": a.Username, "privilege": a.Privilege, "assetId": a.AssetID})
}

// UpsertEscalation records a local privilege-escalation edge between two
// accounts on the same asset (e.g. user -> root via a kernel CVE). weight is the
// attacker effort (lower = easier); Dijkstra minimizes total weight.
func (g *Graph) UpsertEscalation(ctx context.Context, fromID, toID, technique, cwe string, weight float64) (bool, error) {
	return g.edge(ctx, "CAN_ESCALATE", fromID, toID,
		map[string]any{"technique": technique, "cwe": cwe, "weight": weight})
}

// UpsertCredentialReuse records a lateral-movement edge where credentials valid
// for the source account also grant access to the destination account on
// another asset (credential reuse / pass-the-hash).
func (g *Graph) UpsertCredentialReuse(ctx context.Context, fromID, toID string, weight float64) (bool, error) {
	return g.edge(ctx, "CREDENTIAL_REUSE", fromID, toID, map[string]any{"weight": weight})
}

// AutoEscalationWeight maps a finding's risk score to attacker effort: the more
// dangerous (higher risk) the priv-esc vuln, the cheaper (lower weight) the
// escalation edge. Clamped to [0.3, 9].
func AutoEscalationWeight(risk float64) float64 {
	w := 10 - risk
	if w < 0.3 {
		w = 0.3
	}
	if w > 9 {
		w = 9
	}
	return round2(w)
}

// AutoDeriveEscalation turns a privilege-escalation finding into graph capability
// automatically: it ensures a foothold (low-priv) and root (high-priv) account
// exist on the asset and links them with a CAN_ESCALATE edge whose weight comes
// from the finding's risk score. Idempotent — accounts use deterministic IDs and
// the edge keeps the cheapest (lowest-weight) enabling vuln across re-scans.
func (g *Graph) AutoDeriveEscalation(ctx context.Context, assetID, cwe, technique string, risk float64) error {
	weight := AutoEscalationWeight(risk)
	return g.write(ctx,
		`MATCH (asset:Asset {id:$assetId})
		 MERGE (low:Account {id:$footholdId})
		   ON CREATE SET low.username='foothold', low.privilege='user', low.asset_id=$assetId, low.auto=true
		 MERGE (high:Account {id:$rootId})
		   ON CREATE SET high.username='root', high.privilege='root', high.asset_id=$assetId, high.auto=true
		 MERGE (asset)-[:HAS_ACCOUNT]->(low)
		 MERGE (asset)-[:HAS_ACCOUNT]->(high)
		 MERGE (low)-[r:CAN_ESCALATE]->(high)
		   ON CREATE SET r.auto=true, r.weight=$weight, r.technique=$technique, r.cwe=$cwe, r.risk=$risk
		 WITH r
		 WHERE r.weight > $weight
		 SET r.technique=$technique, r.cwe=$cwe, r.risk=$risk, r.weight=$weight`,
		map[string]any{
			"assetId":    assetID,
			"footholdId": AutoAccountID(assetID, "foothold"),
			"rootId":     AutoAccountID(assetID, "root"),
			"weight":     weight, "technique": technique, "cwe": cwe, "risk": risk,
		})
}

// AutoAccountID returns the deterministic node id for an auto-derived account so
// re-scans stay idempotent and callers can address them without a lookup.
func AutoAccountID(assetID, role string) string { return "auto-" + role + "-" + assetID }

// ListAccounts returns the accounts attached to an asset.
func (g *Graph) ListAccounts(ctx context.Context, assetID string) ([]Account, error) {
	recs, err := g.read(ctx,
		`MATCH (asset:Asset {id:$assetId})-[:HAS_ACCOUNT]->(acc:Account)
		 RETURN acc.id AS id, acc.username AS username, acc.privilege AS privilege, acc.asset_id AS asset_id
		 ORDER BY acc.privilege`,
		map[string]any{"assetId": assetID})
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(recs))
	for _, r := range recs {
		id, _ := r.Get("id")
		u, _ := r.Get("username")
		p, _ := r.Get("privilege")
		aid, _ := r.Get("asset_id")
		out = append(out, Account{ID: toStr(id), Username: toStr(u), Privilege: toStr(p), AssetID: toStr(aid)})
	}
	return out, nil
}

// edge upserts a typed relationship between two accounts, returning whether both
// endpoints existed (and the edge was therefore created/updated).
func (g *Graph) edge(ctx context.Context, relType, fromID, toID string, props map[string]any) (bool, error) {
	params := map[string]any{"from": fromID, "to": toID}
	for k, v := range props {
		params[k] = v
	}
	setClauses := ""
	for k := range props {
		setClauses += fmt.Sprintf(" SET r.%s=$%s", k, k)
	}
	cypher := fmt.Sprintf(
		`MATCH (a:Account {id:$from}), (b:Account {id:$to})
		 MERGE (a)-[r:%s]->(b)%s
		 RETURN count(r) AS c`, relType, setClauses)

	recs, err := g.writeReturn(ctx, cypher, params)
	if err != nil {
		return false, err
	}
	if len(recs) == 0 {
		return false, nil
	}
	c, _ := recs[0].Get("c")
	return toInt(c) > 0, nil
}

// PrivEscStep is one weighted edge along a privilege-escalation path.
type PrivEscStep struct {
	Type      string  `json:"type"` // CAN_ESCALATE | CREDENTIAL_REUSE
	Technique string  `json:"technique,omitempty"`
	CWE       string  `json:"cwe,omitempty"`
	Weight    float64 `json:"weight"`
}

// PrivEscNode is one account on a privilege-escalation path.
type PrivEscNode struct {
	AccountID string `json:"account_id"`
	Username  string `json:"username"`
	Privilege string `json:"privilege"`
	Asset     string `json:"asset"`
}

// PrivEscPath is the cheapest (lowest total effort) privilege-escalation chain.
type PrivEscPath struct {
	Accounts  []PrivEscNode `json:"accounts"`
	Steps     []PrivEscStep `json:"steps"`
	TotalCost float64       `json:"total_cost"`
	Found     bool          `json:"found"`
}

// FindPrivEscPath uses apoc.algo.dijkstra to find the minimum-effort privilege
// escalation path from a foothold account to a target privileged account,
// traversing CAN_ESCALATE (intra-host) and CREDENTIAL_REUSE (inter-host) edges.
func (g *Graph) FindPrivEscPath(ctx context.Context, startID, targetID string) (PrivEscPath, error) {
	cypher := `
		MATCH (start:Account {id:$startId}), (target:Account {id:$targetId})
		CALL apoc.algo.dijkstra(start, target, 'CAN_ESCALATE>|CREDENTIAL_REUSE>', 'weight')
		YIELD path, weight
		RETURN [n IN nodes(path) | {
		         id: n.id, username: n.username, privilege: n.privilege,
		         asset: head([ (asset:Asset)-[:HAS_ACCOUNT]->(n) | asset.name ])
		       }] AS accounts,
		       [r IN relationships(path) | {
		         type: type(r), technique: r.technique, cwe: r.cwe, weight: r.weight
		       }] AS steps,
		       weight AS total_cost
		ORDER BY total_cost ASC
		LIMIT 1`

	recs, err := g.read(ctx, cypher, map[string]any{"startId": startID, "targetId": targetID})
	if err != nil {
		return PrivEscPath{}, err
	}
	if len(recs) == 0 {
		return PrivEscPath{Found: false}, nil
	}
	rec := recs[0]
	out := PrivEscPath{Found: true}
	costAny, _ := rec.Get("total_cost")
	out.TotalCost = round2(toFloat(costAny))

	accAny, _ := rec.Get("accounts")
	for _, a := range asSlice(accAny) {
		am, _ := a.(map[string]any)
		out.Accounts = append(out.Accounts, PrivEscNode{
			AccountID: toStr(am["id"]),
			Username:  toStr(am["username"]),
			Privilege: toStr(am["privilege"]),
			Asset:     toStr(am["asset"]),
		})
	}
	stepsAny, _ := rec.Get("steps")
	for _, s := range asSlice(stepsAny) {
		sm, _ := s.(map[string]any)
		out.Steps = append(out.Steps, PrivEscStep{
			Type:      toStr(sm["type"]),
			Technique: toStr(sm["technique"]),
			CWE:       toStr(sm["cwe"]),
			Weight:    round2(toFloat(sm["weight"])),
		})
	}
	return out, nil
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

// Hop is one node along an attack path, with the vulnerability that enables
// compromise of that node (highest-risk exploitable vuln on it).
type Hop struct {
	AssetID     string  `json:"asset_id"`
	AssetName   string  `json:"asset_name"`
	Criticality string  `json:"criticality"`
	Exposure    string  `json:"exposure"`
	ViaVulnTitle string `json:"via_vuln_title,omitempty"`
	ViaVulnCWE  string  `json:"via_vuln_cwe,omitempty"`
	ViaVulnRisk float64 `json:"via_vuln_risk"`
}

// AttackPath is a full chain from an exposed entry point to the target asset.
type AttackPath struct {
	Hops     []Hop   `json:"hops"`
	Length   int     `json:"length"`    // number of edges
	MaxRisk  float64 `json:"max_risk"`  // highest enabling-vuln risk on the path
	PathRisk float64 `json:"path_risk"` // aggregate exposure of the path (avg enabling risk)
}

// FindAttackPaths returns attack paths leading to targetID. A valid path starts
// at an externally-exposed asset and every node on it carries at least one
// exploitable vulnerability (risk >= minRisk). Paths are ranked by enabling risk.
func (g *Graph) FindAttackPaths(ctx context.Context, targetID string, minRisk float64, maxHops int) ([]AttackPath, error) {
	if maxHops < 1 {
		maxHops = 4
	}
	if maxHops > 8 {
		maxHops = 8
	}
	// maxHops is bounds-checked above, so it is safe to interpolate into the
	// variable-length relationship pattern (Cypher can't parameterize bounds).
	cypher := fmt.Sprintf(`
		MATCH (target:Asset {id:$targetId})
		MATCH path = (entry:Asset)-[:CAN_REACH*1..%d]->(target)
		WHERE entry.exposure = 'external'
		  AND ALL(n IN nodes(path) WHERE EXISTS {
		        MATCH (n)-[:HAS_VULN]->(v:Vulnerability) WHERE v.risk >= $minRisk
		      })
		RETURN [n IN nodes(path) | {
		         id: n.id, name: n.name, criticality: n.criticality, exposure: n.exposure,
		         vulns: [ (n)-[:HAS_VULN]->(v:Vulnerability) WHERE v.risk >= $minRisk
		                  | {title: v.title, cwe: v.cwe, risk: v.risk} ]
		       }] AS hops,
		       length(path) AS len
		ORDER BY len ASC
		LIMIT 50`, maxHops)

	records, err := g.read(ctx, cypher, map[string]any{"targetId": targetID, "minRisk": minRisk})
	if err != nil {
		return nil, err
	}

	paths := make([]AttackPath, 0, len(records))
	for _, rec := range records {
		rawHops, _ := rec.Get("hops")
		lenAny, _ := rec.Get("len")
		ap := AttackPath{Length: toInt(lenAny)}
		hopsList, _ := rawHops.([]any)
		var sumRisk float64
		for _, h := range hopsList {
			hm, _ := h.(map[string]any)
			hop := Hop{
				AssetID:     toStr(hm["id"]),
				AssetName:   toStr(hm["name"]),
				Criticality: toStr(hm["criticality"]),
				Exposure:    toStr(hm["exposure"]),
			}
			// pick the highest-risk enabling vuln for this hop
			if vulns, ok := hm["vulns"].([]any); ok {
				top := pickTopVuln(vulns)
				hop.ViaVulnTitle = toStr(top["title"])
				hop.ViaVulnCWE = toStr(top["cwe"])
				hop.ViaVulnRisk = toFloat(top["risk"])
			}
			if hop.ViaVulnRisk > ap.MaxRisk {
				ap.MaxRisk = hop.ViaVulnRisk
			}
			sumRisk += hop.ViaVulnRisk
			ap.Hops = append(ap.Hops, hop)
		}
		if len(ap.Hops) > 0 {
			ap.PathRisk = round2(sumRisk / float64(len(ap.Hops)))
		}
		paths = append(paths, ap)
	}

	// Rank by most dangerous first: highest max enabling risk, then shortest.
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].MaxRisk != paths[j].MaxRisk {
			return paths[i].MaxRisk > paths[j].MaxRisk
		}
		return paths[i].Length < paths[j].Length
	})
	return paths, nil
}

// ---- low-level helpers ----

func (g *Graph) write(ctx context.Context, cypher string, params map[string]any) error {
	session := g.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		return res.Consume(ctx)
	})
	return err
}

// writeReturn runs a write transaction that also yields rows (e.g. MERGE ... RETURN).
func (g *Graph) writeReturn(ctx context.Context, cypher string, params map[string]any) ([]*neo4j.Record, error) {
	session := g.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	out, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		return res.Collect(ctx)
	})
	if err != nil {
		return nil, err
	}
	recs, _ := out.([]*neo4j.Record)
	return recs, nil
}

func (g *Graph) read(ctx context.Context, cypher string, params map[string]any) ([]*neo4j.Record, error) {
	session := g.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	out, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		return res.Collect(ctx)
	})
	if err != nil {
		return nil, err
	}
	recs, _ := out.([]*neo4j.Record)
	return recs, nil
}

func pickTopVuln(vulns []any) map[string]any {
	var top map[string]any
	var best float64 = -1
	for _, v := range vulns {
		vm, _ := v.(map[string]any)
		if r := toFloat(vm["risk"]); r > best {
			best = r
			top = vm
		}
	}
	if top == nil {
		top = map[string]any{}
	}
	return top
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	}
	return 0
}

func toInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }
