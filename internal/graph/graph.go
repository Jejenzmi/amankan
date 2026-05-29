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
