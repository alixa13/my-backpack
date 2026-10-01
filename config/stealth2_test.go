package config

import "testing"

func TestStealth2IsAReverseTransport(t *testing.T) {
	if !IsReverseTransport(STEALTH2) {
		t.Error("stealth2 is not recognised as a reverse transport")
	}
}

func TestStealth2CanLeadAFallbackChain(t *testing.T) {
	if err := ValidateFallbackTransports(STEALTH2, []TransportType{STEALTH}); err != nil {
		t.Errorf("[stealth2, stealth] should validate: %v", err)
	}
}
