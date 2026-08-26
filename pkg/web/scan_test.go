package web

import (
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/config"
)

func TestResolveWebVulnDetectionDisablesModulesWhenGlobalSwitchOff(t *testing.T) {
	resolved := resolveWebVulnDetection(config.VulnDetection{
		Enabled:      false,
		SQLInjection: config.SQLInjectionConfig{Enabled: true},
		LFI:          config.LFIConfig{Enabled: true},
		SSRF:         config.SSRFConfig{Enabled: true},
		Redirect:     config.RedirectConfig{Enabled: true},
		XSS:          config.XSSConfig{Enabled: true},
		Upload:       config.UploadConfig{Enabled: true},
	})

	if resolved.Enabled {
		t.Fatalf("expected global vuln switch to remain disabled")
	}
	if resolved.SQLInjection.Enabled || resolved.LFI.Enabled || resolved.SSRF.Enabled ||
		resolved.Redirect.Enabled || resolved.XSS.Enabled || resolved.Upload.Enabled {
		t.Fatalf("expected all vuln modules to be disabled when global switch is off: %+v", resolved)
	}
}

func TestResolveWebVulnDetectionPreservesModulesWhenGlobalSwitchOn(t *testing.T) {
	resolved := resolveWebVulnDetection(config.VulnDetection{
		Enabled:      true,
		SQLInjection: config.SQLInjectionConfig{Enabled: false},
		LFI:          config.LFIConfig{Enabled: true},
		SSRF:         config.SSRFConfig{Enabled: false},
		Redirect:     config.RedirectConfig{Enabled: true},
		XSS:          config.XSSConfig{Enabled: false},
		Upload:       config.UploadConfig{Enabled: true},
	})

	if !resolved.Enabled {
		t.Fatalf("expected global vuln switch to stay enabled")
	}
	if resolved.SQLInjection.Enabled {
		t.Fatalf("expected per-module SQL switch to be preserved")
	}
	if !resolved.LFI.Enabled || resolved.SSRF.Enabled || !resolved.Redirect.Enabled ||
		resolved.XSS.Enabled || !resolved.Upload.Enabled {
		t.Fatalf("expected per-module switches to be preserved when global switch is on: %+v", resolved)
	}
}
