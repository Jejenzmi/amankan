-- Per-asset scan authorization (Layer 3). An asset is only scanned for real in
-- production when it has been explicitly authorized — an auditable, granular
-- record that the operator is permitted to test this target.

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS scan_authorized BOOLEAN NOT NULL DEFAULT false;
