/**
 * ml.js
 * Machine Learning Predictor.
 * Implements a Client-Side Random Forest classifier (ensemble of decision trees).
 * Evaluates permission sets to output malware probability.
 * Supports tree path tracing for visual explanation.
 */

const MLPredictor = {
    // Feature list mapping index to permission string
    features: [
        { name: "SEND_SMS", permission: "android.permission.SEND_SMS", label: "Send SMS" },
        { name: "RECEIVE_SMS", permission: "android.permission.RECEIVE_SMS", label: "Receive SMS" },
        { name: "RECORD_AUDIO", permission: "android.permission.RECORD_AUDIO", label: "Record Audio" },
        { name: "READ_CONTACTS", permission: "android.permission.READ_CONTACTS", label: "Read Contacts" },
        { name: "ACCESS_FINE_LOCATION", permission: "android.permission.ACCESS_FINE_LOCATION", label: "Fine Location" },
        { name: "INTERNET", permission: "android.permission.INTERNET", label: "Internet" },
        { name: "SYSTEM_ALERT_WINDOW", permission: "android.permission.SYSTEM_ALERT_WINDOW", label: "Overlay Window" },
        { name: "RECEIVE_BOOT_COMPLETED", permission: "android.permission.RECEIVE_BOOT_COMPLETED", label: "Start at Boot" },
        { name: "CAMERA", permission: "android.permission.CAMERA", label: "Camera" },
        { name: "BIND_DEVICE_ADMIN", permission: "android.permission.BIND_DEVICE_ADMIN", label: "Device Admin" }
    ],

    // Fixed feature importances for Random Forest representation
    featureImportances: {
        "SEND_SMS": 0.22,
        "BIND_DEVICE_ADMIN": 0.18,
        "RECORD_AUDIO": 0.15,
        "SYSTEM_ALERT_WINDOW": 0.12,
        "RECEIVE_SMS": 0.11,
        "READ_CONTACTS": 0.08,
        "ACCESS_FINE_LOCATION": 0.06,
        "RECEIVE_BOOT_COMPLETED": 0.04,
        "INTERNET": 0.03,
        "CAMERA": 0.01
    },

    // Tree definitions for ensemble model
    // Nodes specify the feature to test, yes/no branches, or leaf nodes with prediction values.
    trees: [
        // Tree 1: Focuses on SMS-based abuse and window overlays
        {
            id: 1,
            name: "Sms & Overlay Classifier",
            root: {
                id: "t1_n1",
                feature: "SEND_SMS",
                yes: {
                    id: "t1_n2",
                    feature: "RECEIVE_SMS",
                    yes: { id: "t1_l1", leaf: true, prediction: 0.95, text: "High Threat: SMS Trojan Interceptor" },
                    no: {
                        id: "t1_n3",
                        feature: "INTERNET",
                        yes: { id: "t1_l2", leaf: true, prediction: 0.80, text: "Suspicious: Silent SMS Outbox Transmitter" },
                        no: { id: "t1_l3", leaf: true, prediction: 0.55, text: "Suspicious: Local SMS Sender" }
                    }
                },
                no: {
                    id: "t1_n4",
                    feature: "SYSTEM_ALERT_WINDOW",
                    yes: {
                        id: "t1_n5",
                        feature: "RECEIVE_BOOT_COMPLETED",
                        yes: { id: "t1_l4", leaf: true, prediction: 0.85, text: "Threat: LockScreen Overlay Ransomware" },
                        no: { id: "t1_l5", leaf: true, prediction: 0.60, text: "Suspicious: Persistent Draw-Over App" }
                    },
                    no: { id: "t1_l6", leaf: true, prediction: 0.10, text: "Safe: Minimal SMS/UI Overlay Risk" }
                }
            }
        },
        // Tree 2: Focuses on Spyware capabilities (Audio, Contacts, Camera)
        {
            id: 2,
            name: "Spyware & Data Leak Classifier",
            root: {
                id: "t2_n1",
                feature: "RECORD_AUDIO",
                yes: {
                    id: "t2_n2",
                    feature: "READ_CONTACTS",
                    yes: {
                        id: "t2_n3",
                        feature: "INTERNET",
                        yes: { id: "t2_l1", leaf: true, prediction: 0.90, text: "High Threat: Audio-Recording Spyware" },
                        no: { id: "t2_l2", leaf: true, prediction: 0.65, text: "Suspicious: Offline Surveillance App" }
                    },
                    no: {
                        id: "t2_n4",
                        feature: "CAMERA",
                        yes: { id: "t2_l3", leaf: true, prediction: 0.70, text: "Suspicious: Covert Media Recorder" },
                        no: { id: "t2_l4", leaf: true, prediction: 0.25, text: "Moderate: Audio Recording Utility" }
                    }
                },
                no: {
                    id: "t2_n5",
                    feature: "READ_CONTACTS",
                    yes: {
                        id: "t2_n6",
                        feature: "INTERNET",
                        yes: { id: "t2_l5", leaf: true, prediction: 0.50, text: "Moderate: Contact Harvester" },
                        no: { id: "t2_l6", leaf: true, prediction: 0.15, text: "Safe: Offline Contacts Utility" }
                    },
                    no: { id: "t2_l7", leaf: true, prediction: 0.05, text: "Safe: No Spyware Indicators" }
                }
            }
        },
        // Tree 3: Focuses on Location Tracking & Admin exploits
        {
            id: 3,
            name: "Location & Admin Exploit Classifier",
            root: {
                id: "t3_n1",
                feature: "BIND_DEVICE_ADMIN",
                yes: {
                    id: "t3_n2",
                    feature: "RECEIVE_BOOT_COMPLETED",
                    yes: { id: "t3_l1", leaf: true, prediction: 0.98, text: "Critical Threat: Admin-Level Persistence Tool" },
                    no: { id: "t3_l2", leaf: true, prediction: 0.85, text: "High Threat: Unsecured Device Manager Admin" }
                },
                no: {
                    id: "t3_n3",
                    feature: "ACCESS_FINE_LOCATION",
                    yes: {
                        id: "t3_n4",
                        feature: "INTERNET",
                        yes: { id: "t3_l3", leaf: true, prediction: 0.60, text: "Suspicious: Real-Time Location Tracker" },
                        no: { id: "t3_l4", leaf: true, prediction: 0.20, text: "Safe: GPS Mapping Tool (Offline)" }
                    },
                    no: {
                        id: "t3_n5",
                        feature: "INTERNET",
                        yes: { id: "t3_l5", leaf: true, prediction: 0.20, text: "Safe: Standard Network Access" },
                        no: { id: "t3_l6", leaf: true, prediction: 0.02, text: "Safe: Zero Network/Location Footprint" }
                    }
                }
            }
        }
    ],

    /**
     * Extracts features from a list of permissions into a boolean object.
     * @param {Array<string>} permissions - Permissions from manifest.
     * @returns {Object} Key-value pair of features.
     */
    extractFeatureVector(permissions) {
        const vector = {};
        const normPermissions = permissions.map(p => p.toLowerCase().trim());
        
        this.features.forEach(f => {
            vector[f.name] = normPermissions.includes(f.permission.toLowerCase()) ? 1 : 0;
        });
        return vector;
    },

    /**
     * Traverses a single decision tree.
     * @param {Object} tree - Tree root.
     * @param {Object} vector - App feature vector.
     * @param {Array} pathCollector - Array to collect traversed node IDs.
     * @returns {Object} Leaf prediction and text summary.
     */
    traverseTree(node, vector, pathCollector) {
        pathCollector.push(node.id);
        
        if (node.leaf) {
            return {
                prediction: node.prediction,
                decisionText: node.text
            };
        }

        const featureVal = vector[node.feature];
        const nextNode = featureVal === 1 ? node.yes : node.no;
        return this.traverseTree(nextNode, vector, pathCollector);
    },

    /**
     * Executes the Random Forest ensemble prediction.
     * @param {Array<string>} permissions - App permissions.
     * @returns {Object} Object containing probability, classifications, and details.
     */
    predict(permissions) {
        const vector = this.extractFeatureVector(permissions);
        const results = [];
        const traces = {};

        this.trees.forEach(tree => {
            const pathCollector = [];
            const treeResult = this.traverseTree(tree.root, vector, pathCollector);
            results.push(treeResult.prediction);
            traces[tree.id] = {
                path: pathCollector,
                prediction: treeResult.prediction,
                decisionText: treeResult.decisionText
            };
        });

        // Ensemble Average
        const averageProbability = results.reduce((a, b) => a + b, 0) / results.length;
        const percentScore = Math.round(averageProbability * 100);

        // Classification based on PRD threshold
        // 0-20 Safe, 21-50 Moderate, 51-80 Suspicious, 81-100 Malicious
        let classification = "Safe";
        if (percentScore > 80) classification = "Malicious";
        else if (percentScore > 50) classification = "Suspicious";
        else if (percentScore > 20) classification = "Moderate";

        return {
            probability: averageProbability,
            riskScore: percentScore,
            classification,
            vector,
            treeDetails: traces
        };
    }
};

window.MLPredictor = MLPredictor;
