/**
 * engine.js
 * Rule-Based Malware Engine.
 * Scans permission lists against active detection rules stored in the database.
 */

const RuleEngine = {
    /**
     * Scans a list of app permissions and returns matched rules and rule-based risk score.
     * @param {Array<string>} appPermissions - List of permissions requested by the app.
     * @returns {Object} Scan results containing matchedRules, ruleRiskScore, and findings.
     */
    analyze(appPermissions) {
        const rules = window.Database.getRules();
        const matchedRules = [];
        let ruleRiskScore = 0;
        const findings = [];

        // Normalize permission list for easy case-insensitive matching
        const permissionsLower = appPermissions.map(p => p.toLowerCase().trim());

        rules.forEach(rule => {
            // Check if all permissions in the rule are present in the app's permission list
            const allMatched = rule.permissions.every(rulePerm => {
                return permissionsLower.includes(rulePerm.toLowerCase().trim());
            });

            if (allMatched && rule.permissions.length > 0) {
                matchedRules.push(rule.rule_name);
                // We track the highest weight as the rule engine's risk contribution
                if (rule.risk_weight > ruleRiskScore) {
                    ruleRiskScore = rule.risk_weight;
                }
                findings.push({
                    name: rule.rule_name,
                    description: rule.description,
                    weight: rule.risk_weight,
                    triggerPermissions: rule.permissions
                });
            }
        });

        // Let's also add some basic dynamic alerts if the app asks for excessive dangerous permissions
        // even if they don't match a specific configured rule.
        const DANGEROUS_PERMISSIONS = [
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.READ_PHONE_STATE",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.RECEIVE_BOOT_COMPLETED"
        ];

        const dangerousCount = permissionsLower.filter(p => {
            return DANGEROUS_PERMISSIONS.some(dp => dp.toLowerCase() === p);
        }).length;

        // If no specific rule matched but there are multiple dangerous permissions,
        // compute a baseline permission-density risk score (10 points per dangerous permission, up to 40)
        if (ruleRiskScore === 0 && dangerousCount > 0) {
            ruleRiskScore = Math.min(40, dangerousCount * 10);
            if (dangerousCount >= 3) {
                findings.push({
                    name: "Excessive_Dangerous_Permissions",
                    description: `The application requests ${dangerousCount} dangerous permissions, which is highly unusual for general utility apps.`,
                    weight: ruleRiskScore,
                    triggerPermissions: appPermissions.filter(p => DANGEROUS_PERMISSIONS.some(dp => dp.toLowerCase() === p.toLowerCase()))
                });
            }
        }

        return {
            matchedRules,
            ruleRiskScore,
            findings
        };
    }
};

window.RuleEngine = RuleEngine;
