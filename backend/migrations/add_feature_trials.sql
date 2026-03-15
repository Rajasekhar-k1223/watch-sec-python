-- Migration: Add FeatureTrials table for 1-hour trial tracking
-- Date: 2026-02-13

CREATE TABLE IF NOT EXISTS FeatureTrials (
    Id INT PRIMARY KEY AUTO_INCREMENT,
    TenantId INT NOT NULL,
    FeatureName VARCHAR(100) NOT NULL,
    TrialStartedAt DATETIME NOT NULL,
    TrialExpiresAt DATETIME NOT NULL,
    IsActive BOOLEAN DEFAULT TRUE,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tenant_id (TenantId),
    INDEX idx_is_active (IsActive),
    UNIQUE KEY unique_tenant_feature (TenantId, FeatureName),
    FOREIGN KEY (TenantId) REFERENCES Tenants(Id) ON DELETE CASCADE
);
