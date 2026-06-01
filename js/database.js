/**
 * database.js
 * Emulates the SQLite database 'malware_detector.db' using browser localStorage.
 * Provides data persistence, default rule definitions, and a mock SQL query engine.
 */

const DB_KEYS = {
    HISTORY: 'malware_detector_scan_history',
    RULES: 'malware_detector_rules'
};

// Initial system rules
const DEFAULT_RULES = [
    {
        id: 1,
        rule_name: "SMS_Trojan_Activity",
        description: "App requests both SEND_SMS and RECEIVE_SMS along with starting at boot. Highly characteristic of silent SMS interceptors.",
        permissions: ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.RECEIVE_BOOT_COMPLETED"],
        risk_weight: 90
    },
    {
        id: 2,
        rule_name: "Spyware_SpyMic",
        description: "App requests audio recording and contacts list access alongside internet permissions. Often indicates covert eavesdropping.",
        permissions: ["android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.INTERNET"],
        risk_weight: 85
    },
    {
        id: 3,
        rule_name: "Ransomware_LockScreen",
        description: "App demands window overlay and device admin capabilities to lock the screen and display alerts.",
        permissions: ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_DEVICE_ADMIN"],
        risk_weight: 95
    },
    {
        id: 4,
        rule_name: "Location_Tracker",
        description: "App requests precise location coordinates and accesses internet. May leak device location without permission.",
        permissions: ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
        risk_weight: 45
    },
    {
        id: 5,
        rule_name: "Silent_Installer",
        description: "App requests ability to request package installation and delete packages. Highly suspicious unless it is an app store.",
        permissions: ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.DELETE_PACKAGES"],
        risk_weight: 80
    }
];

// Initial mock scan history
const DEFAULT_HISTORY = [
    {
        id: 101,
        app_name: "WhatsApp",
        package_name: "com.whatsapp",
        risk_score: 12,
        classification: "Safe",
        permissions_scanned: ["android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.CAMERA", "android.permission.INTERNET"],
        matched_rules: [],
        scan_date: "2026-05-25 14:32:05"
    },
    {
        id: 102,
        app_name: "Instagram",
        package_name: "com.instagram.android",
        risk_score: 47,
        classification: "Moderate",
        permissions_scanned: ["android.permission.INTERNET", "android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.ACCESS_FINE_LOCATION"],
        matched_rules: ["Location_Tracker"],
        scan_date: "2026-05-25 15:45:10"
    },
    {
        id: 103,
        app_name: "UnknownSmsSvc",
        package_name: "com.sms.covert.service",
        risk_score: 90,
        classification: "Malicious",
        permissions_scanned: ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"],
        matched_rules: ["SMS_Trojan_Activity"],
        scan_date: "2026-05-26 09:12:30"
    }
];

const Database = {
    init() {
        if (!localStorage.getItem(DB_KEYS.RULES)) {
            localStorage.setItem(DB_KEYS.RULES, JSON.stringify(DEFAULT_RULES));
        }
        if (!localStorage.getItem(DB_KEYS.HISTORY)) {
            localStorage.setItem(DB_KEYS.HISTORY, JSON.stringify(DEFAULT_HISTORY));
        }
        console.log("Simulated SQLite 'malware_detector.db' initialized successfully.");
    },

    getRules() {
        return JSON.parse(localStorage.getItem(DB_KEYS.RULES)) || [];
    },

    saveRules(rules) {
        localStorage.setItem(DB_KEYS.RULES, JSON.stringify(rules));
    },

    saveRule(rule) {
        const rules = this.getRules();
        if (rule.id) {
            // Update
            const idx = rules.findIndex(r => r.id === parseInt(rule.id));
            if (idx !== -1) {
                rules[idx] = { ...rules[idx], ...rule };
            }
        } else {
            // Create
            rule.id = rules.length > 0 ? Math.max(...rules.map(r => r.id)) + 1 : 1;
            rules.push(rule);
        }
        this.saveRules(rules);
        return rule;
    },

    deleteRule(id) {
        const rules = this.getRules();
        const filtered = rules.filter(r => r.id !== parseInt(id));
        this.saveRules(filtered);
        return true;
    },

    getHistory() {
        return JSON.parse(localStorage.getItem(DB_KEYS.HISTORY)) || [];
    },

    saveHistory(history) {
        localStorage.setItem(DB_KEYS.HISTORY, JSON.stringify(history));
    },

    addHistoryRecord(record) {
        const history = this.getHistory();
        record.id = history.length > 0 ? Math.max(...history.map(h => h.id)) + 1 : 101;
        if (!record.scan_date) {
            const now = new Date();
            record.scan_date = now.toISOString().slice(0, 19).replace('T', ' ');
        }
        history.unshift(record); // Prepend to show newest first
        this.saveHistory(history);
        return record;
    },

    clearHistory() {
        localStorage.setItem(DB_KEYS.HISTORY, JSON.stringify([]));
        return true;
    },

    /**
     * Executes mock SQL queries on local data.
     * Supports basic SELECT, UPDATE, DELETE, INSERT queries for history and rules.
     */
    executeSQL(queryStr) {
        const cleaned = queryStr.trim().replace(/;$/, '');
        const selectRegex = /^SELECT\s+(.+?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?$/i;
        const updateRegex = /^UPDATE\s+(\w+)\s+SET\s+(.+?)(?:\s+WHERE\s+(.+))?$/i;
        const deleteRegex = /^DELETE\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?$/i;
        const insertRegex = /^INSERT\s+INTO\s+(\w+)\s*\((.+?)\)\s*VALUES\s*\((.+?)\)$/i;

        try {
            if (selectRegex.test(cleaned)) {
                const match = cleaned.match(selectRegex);
                const fieldsStr = match[1].trim();
                const tableName = match[2].trim().toLowerCase();
                const whereClause = match[3] ? match[3].trim() : null;

                let data = [];
                if (tableName === 'scan_history' || tableName === 'history') {
                    data = this.getHistory();
                } else if (tableName === 'malware_rules' || tableName === 'rules') {
                    data = this.getRules();
                } else {
                    throw new Error(`Table '${tableName}' not found in database.`);
                }

                // Filter by WHERE
                let filteredData = data;
                if (whereClause) {
                    filteredData = this._applyWhereFilter(data, whereClause);
                }

                // Select fields
                const fields = fieldsStr.split(',').map(f => f.trim());
                const result = filteredData.map(row => {
                    if (fieldsStr === '*') return row;
                    let projected = {};
                    fields.forEach(f => {
                        if (row[f] !== undefined) {
                            projected[f] = row[f];
                        }
                    });
                    return projected;
                });

                return {
                    success: true,
                    type: 'SELECT',
                    rowCount: result.length,
                    columns: fieldsStr === '*' ? Object.keys(data[0] || {}) : fields,
                    rows: result
                };

            } else if (deleteRegex.test(cleaned)) {
                const match = cleaned.match(deleteRegex);
                const tableName = match[1].trim().toLowerCase();
                const whereClause = match[2] ? match[2].trim() : null;

                let dataKey = '';
                let data = [];

                if (tableName === 'scan_history' || tableName === 'history') {
                    dataKey = DB_KEYS.HISTORY;
                    data = this.getHistory();
                } else if (tableName === 'malware_rules' || tableName === 'rules') {
                    dataKey = DB_KEYS.RULES;
                    data = this.getRules();
                } else {
                    throw new Error(`Table '${tableName}' not found in database.`);
                }

                let remaining = [];
                let deletedCount = 0;

                if (!whereClause) {
                    deletedCount = data.length;
                    remaining = [];
                } else {
                    data.forEach(row => {
                        if (this._evaluateWhereRow(row, whereClause)) {
                            deletedCount++;
                        } else {
                            remaining.push(row);
                        }
                    });
                }

                localStorage.setItem(dataKey, JSON.stringify(remaining));
                return {
                    success: true,
                    type: 'DELETE',
                    message: `Query OK, ${deletedCount} row(s) affected.`
                };

            } else if (updateRegex.test(cleaned)) {
                const match = cleaned.match(updateRegex);
                const tableName = match[1].trim().toLowerCase();
                const setClause = match[2].trim();
                const whereClause = match[3] ? match[3].trim() : null;

                let dataKey = '';
                let data = [];

                if (tableName === 'scan_history' || tableName === 'history') {
                    dataKey = DB_KEYS.HISTORY;
                    data = this.getHistory();
                } else if (tableName === 'malware_rules' || tableName === 'rules') {
                    dataKey = DB_KEYS.RULES;
                    data = this.getRules();
                } else {
                    throw new Error(`Table '${tableName}' not found in database.`);
                }

                // Parse SET key=value pairs
                // Example: risk_weight = 80, description = 'Hello'
                const setPairs = {};
                const setParts = setClause.split(/,(?=(?:[^']*'[^']*')*[^']*$)/); // Split commas outside quotes
                setParts.forEach(p => {
                    const eqIdx = p.indexOf('=');
                    if (eqIdx !== -1) {
                        const key = p.substring(0, eqIdx).trim();
                        let val = p.substring(eqIdx + 1).trim();
                        // Strip quotes if string
                        if ((val.startsWith("'") && val.endsWith("'")) || (val.startsWith('"') && val.endsWith('"'))) {
                            val = val.substring(1, val.length - 1);
                        } else if (!isNaN(val)) {
                            val = Number(val);
                        }
                        setPairs[key] = val;
                    }
                });

                let updatedCount = 0;
                const updatedData = data.map(row => {
                    if (!whereClause || this._evaluateWhereRow(row, whereClause)) {
                        updatedCount++;
                        return { ...row, ...setPairs };
                    }
                    return row;
                });

                localStorage.setItem(dataKey, JSON.stringify(updatedData));
                return {
                    success: true,
                    type: 'UPDATE',
                    message: `Query OK, ${updatedCount} row(s) affected.`
                };

            } else if (insertRegex.test(cleaned)) {
                const match = cleaned.match(insertRegex);
                const tableName = match[1].trim().toLowerCase();
                const columnsStr = match[2].trim();
                const valuesStr = match[3].trim();

                let dataKey = '';
                let data = [];

                if (tableName === 'scan_history' || tableName === 'history') {
                    dataKey = DB_KEYS.HISTORY;
                    data = this.getHistory();
                } else if (tableName === 'malware_rules' || tableName === 'rules') {
                    dataKey = DB_KEYS.RULES;
                    data = this.getRules();
                } else {
                    throw new Error(`Table '${tableName}' not found in database.`);
                }

                const columns = columnsStr.split(',').map(c => c.trim());
                // Split values, respecting single quotes
                const values = valuesStr.split(/,(?=(?:[^']*'[^']*')*[^']*$)/).map(v => {
                    let trimVal = v.trim();
                    if ((trimVal.startsWith("'") && trimVal.endsWith("'")) || (trimVal.startsWith('"') && trimVal.endsWith('"'))) {
                        return trimVal.substring(1, trimVal.length - 1);
                    }
                    if (!isNaN(trimVal) && trimVal !== '') {
                        return Number(trimVal);
                    }
                    return trimVal;
                });

                if (columns.length !== values.length) {
                    throw new Error("Column count doesn't match value count.");
                }

                const newRow = {};
                // Assign ID
                newRow.id = data.length > 0 ? Math.max(...data.map(d => d.id)) + 1 : 1;

                columns.forEach((col, idx) => {
                    newRow[col] = values[idx];
                });

                // Default fields
                if (tableName.includes('history')) {
                    if (!newRow.scan_date) {
                        newRow.scan_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
                    }
                    if (!newRow.matched_rules) newRow.matched_rules = [];
                    if (!newRow.permissions_scanned) newRow.permissions_scanned = [];
                }

                data.push(newRow);
                localStorage.setItem(dataKey, JSON.stringify(data));

                return {
                    success: true,
                    type: 'INSERT',
                    message: `Query OK, 1 row affected (ID: ${newRow.id}).`
                };

            } else {
                throw new Error("Unsupported query syntax. Supported: SELECT, INSERT, UPDATE, DELETE.");
            }
        } catch (err) {
            return {
                success: false,
                message: `SQLite Error: ${err.message}`
            };
        }
    },

    _applyWhereFilter(data, whereClause) {
        return data.filter(row => this._evaluateWhereRow(row, whereClause));
    },

    _evaluateWhereRow(row, whereClause) {
        // Handle simple single condition, e.g., id = 101 or classification = 'Malicious'
        const parts = whereClause.split(/\s*=\s*/);
        if (parts.length === 2) {
            const key = parts[0].trim();
            let val = parts[1].trim();

            if ((val.startsWith("'") && val.endsWith("'")) || (val.startsWith('"') && val.endsWith('"'))) {
                val = val.substring(1, val.length - 1);
            } else if (!isNaN(val)) {
                val = Number(val);
            }

            if (row[key] === undefined) return false;
            return String(row[key]).toLowerCase() === String(val).toLowerCase();
        }
        // Fallback: match true for now if query is complex
        return true;
    }
};

// Initialize DB immediately when database.js loads
Database.init();
window.Database = Database;
