package repo

import (
	"path/filepath"
	"testing"
	"time"

	"go-backend/internal/store/model"
)

func TestBackupRoundTripsTunnelProbeTarget(t *testing.T) {
	source, err := Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatalf("open source repo: %v", err)
	}
	defer source.Close()

	now := time.Now().UnixMilli()
	if err := source.DB().Exec(`
		INSERT INTO tunnel(id, name, traffic_ratio, type, protocol, flow, created_time, updated_time, status, in_ip, inx, probe_target_host, probe_target_port)
		VALUES(20, 'backup-target', 1, 2, 'tls', 1, ?, ?, 1, '', 1, 'speed.example.com', 8443)
	`, now, now).Error; err != nil {
		t.Fatalf("insert source tunnel: %v", err)
	}

	backup, err := source.ExportAll()
	if err != nil {
		t.Fatalf("export backup: %v", err)
	}
	if len(backup.Tunnels) != 1 {
		t.Fatalf("expected one exported tunnel, got %d", len(backup.Tunnels))
	}
	if backup.Tunnels[0].ProbeTargetHost != "speed.example.com" || backup.Tunnels[0].ProbeTargetPort != 8443 {
		t.Fatalf("unexpected exported probe target: %+v", backup.Tunnels[0])
	}

	dest, err := Open(filepath.Join(t.TempDir(), "dest.db"))
	if err != nil {
		t.Fatalf("open dest repo: %v", err)
	}
	defer dest.Close()

	result, err := dest.Import(backup, []string{"tunnels"})
	if err != nil {
		t.Fatalf("import backup: %v", err)
	}
	if result.TunnelsImported != 1 {
		t.Fatalf("expected one imported tunnel, got %d", result.TunnelsImported)
	}

	items, err := dest.ListTunnels()
	if err != nil {
		t.Fatalf("list imported tunnels: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one imported tunnel item, got %d", len(items))
	}
	if items[0]["probeTargetHost"] != "speed.example.com" || items[0]["probeTargetPort"] != 8443 {
		t.Fatalf("unexpected imported probe target: %+v", items[0])
	}
}

func TestExportAllOmitsSensitiveConfigs(t *testing.T) {
	r, err := Open(filepath.Join(t.TempDir(), "export.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	seedConfig(t, r, "app_name", "FLVX")
	seedConfig(t, r, "app_logo", "logo")
	seedConfig(t, r, "app_favicon", "favicon")
	seedConfig(t, r, "app_bg_image", "bg")
	seedConfig(t, r, "cloudflare_site_key", "site-key")
	seedConfig(t, r, "jwt_secret", "jwt-secret")
	seedConfig(t, r, "license_key", "license-secret")
	seedConfig(t, r, "cloudflare_secret_key", "cloudflare-secret")

	for _, tc := range []struct {
		name   string
		export func() (*model.BackupData, error)
	}{
		{name: "ExportAll", export: r.ExportAll},
		{name: "ExportPartial", export: func() (*model.BackupData, error) { return r.ExportPartial([]string{"configs"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backup, err := tc.export()
			if err != nil {
				t.Fatalf("export backup: %v", err)
			}
			if backup.Configs["app_name"] != "FLVX" {
				t.Fatalf("expected public config in export, got %+v", backup.Configs)
			}
			if backup.Configs["cloudflare_site_key"] != "site-key" {
				t.Fatalf("expected public config in export, got %+v", backup.Configs)
			}
			for _, key := range []string{"jwt_secret", "license_key", "cloudflare_secret_key"} {
				if _, ok := backup.Configs[key]; ok {
					t.Fatalf("expected %s to be omitted from export, got %+v", key, backup.Configs)
				}
			}
		})
	}
}

func TestImportIgnoresSensitiveConfigs(t *testing.T) {
	r, err := Open(filepath.Join(t.TempDir(), "import.db"))
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()

	seedConfig(t, r, "app_name", "before")
	seedConfig(t, r, "jwt_secret", "jwt-before")
	seedConfig(t, r, "license_key", "license-before")
	seedConfig(t, r, "cloudflare_secret_key", "cloudflare-before")

	backup := &model.BackupData{Configs: map[string]string{
		"app_name":              "after",
		"jwt_secret":            "jwt-after",
		"license_key":           "license-after",
		"cloudflare_secret_key": "cloudflare-after",
	}}

	result, err := r.Import(backup, []string{"configs"})
	if err != nil {
		t.Fatalf("import backup: %v", err)
	}
	if result.ConfigsImported != 1 {
		t.Fatalf("expected one imported config, got %d", result.ConfigsImported)
	}

	assertConfigValue(t, r, "app_name", "after")
	assertConfigValue(t, r, "jwt_secret", "jwt-before")
	assertConfigValue(t, r, "license_key", "license-before")
	assertConfigValue(t, r, "cloudflare_secret_key", "cloudflare-before")
}

func seedConfig(t *testing.T, r *Repository, name, value string) {
	t.Helper()
	if err := r.DB().Exec(`
		INSERT INTO vite_config(name, value, time)
		VALUES(?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value, time = excluded.time
	`, name, value, time.Now().UnixMilli()).Error; err != nil {
		t.Fatalf("seed config %s: %v", name, err)
	}
}

func assertConfigValue(t *testing.T, r *Repository, name, want string) {
	t.Helper()
	cfg, err := r.GetConfigByName(name)
	if err != nil {
		t.Fatalf("get config %s: %v", name, err)
	}
	if cfg == nil || cfg.Value != want {
		t.Fatalf("expected config %s=%q, got %+v", name, want, cfg)
	}
}
