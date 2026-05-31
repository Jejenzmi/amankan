package sla

import (
	"testing"
	"time"

	"github.com/amankan/amankan/internal/models"
)

var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestDueDateBySeverity(t *testing.T) {
	if got := DueDate(models.SevCritical, base); !got.Equal(base.Add(7 * 24 * time.Hour)) {
		t.Errorf("critical due = %v, want +7d", got)
	}
	if got := DueDate(models.SevHigh, base); !got.Equal(base.Add(30 * 24 * time.Hour)) {
		t.Errorf("high due = %v, want +30d", got)
	}
	// unknown severity falls back to medium window (90d)
	if got := DueDate(models.Severity("weird"), base); !got.Equal(base.Add(90 * 24 * time.Hour)) {
		t.Errorf("unknown severity due = %v, want +90d", got)
	}
}

func TestBreached(t *testing.T) {
	// critical opened at base, now 10 days later → past the 7d window → breached
	now := base.Add(10 * 24 * time.Hour)
	if !Breached(models.FindingOpen, models.SevCritical, base, now) {
		t.Error("overdue open critical should be breached")
	}
	// within window → not breached
	if Breached(models.FindingOpen, models.SevCritical, base, base.Add(3*24*time.Hour)) {
		t.Error("critical within 7d should not be breached")
	}
	// resolved findings never breach, even if overdue
	if Breached(models.FindingRemediated, models.SevCritical, base, now) {
		t.Error("remediated finding must never be breached")
	}
	if Breached(models.FindingFalsePositive, models.SevCritical, base, now) {
		t.Error("false-positive finding must never be breached")
	}
}

func TestDaysRemaining(t *testing.T) {
	// high = 30d window; 10 days elapsed → ~20 remaining
	now := base.Add(10 * 24 * time.Hour)
	if got := DaysRemaining(models.SevHigh, base, now); got != 20 {
		t.Errorf("days remaining = %d, want 20", got)
	}
	// overdue → negative
	if got := DaysRemaining(models.SevCritical, base, base.Add(10*24*time.Hour)); got >= 0 {
		t.Errorf("overdue days remaining = %d, want negative", got)
	}
}
