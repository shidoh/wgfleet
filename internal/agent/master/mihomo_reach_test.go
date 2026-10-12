package master

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A function that reads where mihomo listens must also consult where mihomo IS.
//
// `spec.Master.BindAddress` and `spec.Master.ExternalController` are the addresses
// mihomo binds ON THE HOST. Once client interception moves into mihomo's own
// network namespace they name something it cannot bind — so any code that reads
// one without also consulting the attachment is asking about a machine that is no
// longer there.
//
// This is asserted over the SET of call sites rather than per site, because the
// defect is the set. Four places needed the change; review and the stand caught
// three. The fourth — mihomoRedirPlanner, which probes the redirect listener and
// RESTARTS mihomo when it cannot find it — reached production on 2026-09-05: it
// restarted mihomo every pass, each restart re-initialised the userspace WireGuard
// devices, and three exits fell out of the balancer within three minutes.
//
// A per-site unit test would not have caught that, and neither would a file-level
// allow-list: the miss was in the same file as two of the fixes.
func TestReadingMihomosHostAddressRequiresConsultingTheMove(t *testing.T) {
	// The namespace-aware vocabulary. Naming any of these is proof the function
	// asked the second question.
	aware := map[string]bool{
		"ClashAPIAddr": true, "NetnsPeerIP": true, "NetnsHostIP": true,
		"netnsAttached": true, "NetnsWanted": true, "NetnsPeerAddr": true,
		"attached": true, "inNetns": true,
	}
	// Functions exempt because they do not reach mihomo at all. Each needs a reason.
	exempt := map[string]string{
		"masterMgmtAddr":   "derives the MANAGEMENT address for wg-easy's UI; never dials mihomo",
		"dashboardPlanner": "renders an operator-facing URL, never dials it",
		"dnsPlanner":       "binds the client gateway for blocky; unrelated to mihomo's listeners",
		// Reads the field as a PRESENCE test — "has the controller resolved a gateway
		// yet" — to decide whether to render the accept for the TPROXY mark. It never
		// uses the value as an address. After the move the host stops marking, so the
		// accept is dead rather than wrong.
		"firewallPlanner": "presence test only; the value is never used as an address",
		// The one reader that WANTS the host's address: it is the destination a
		// namespace-local dial is matched on before being redirected to mihomo's real
		// one. Nothing connects to the value.
		"operatorAPIAddr": "the match of a redirect into the namespace, never a dial target",
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			var readsHostAddr string
			var line int
			var sawAware bool
			ast.Inspect(fn, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				switch id.Name {
				case "ExternalController", "BindAddress":
					if readsHostAddr == "" {
						readsHostAddr, line = id.Name, fset.Position(id.Pos()).Line
					}
				default:
					if aware[id.Name] {
						sawAware = true
					}
				}
				return true
			})
			if readsHostAddr == "" || sawAware {
				continue
			}
			owner := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				owner = recvTypeName(fn.Recv.List[0].Type)
			}
			if why, ok := exempt[owner]; ok {
				_ = why
				continue
			}
			t.Errorf("%s:%d — %s reads spec.Master.%s and never consults where mihomo is. "+
				"That address is the HOST's; after the interception moves, mihomo does not bind it. "+
				"Use ClashAPIAddr / NetnsPeerIP, or add %q to the exempt list with the reason it "+
				"never reaches mihomo.", name, line, owner, readsHostAddr, owner)
		}
	}
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}
