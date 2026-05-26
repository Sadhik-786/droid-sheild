/**
 * app.js
 * Main UI Controller and Client-Server Network Simulator.
 * Integrates database, rule engine, machine learning model, and manifest scanning logic.
 * Manages tab transitions, visual charts, custom rule editors, and mock query console.
 */

document.addEventListener("DOMContentLoaded", () => {
    // ---------------------------------------------------------
    // 1. STATE VARIABLES
    // ---------------------------------------------------------
    let currentChart = null;
    let featureChart = null;
    let currentScanData = null;

    // ---------------------------------------------------------
    // 2. DOM ELEMENTS CACHE
    // ---------------------------------------------------------
    const navItems = document.querySelectorAll("[data-tab]");
    const tabPanels = document.querySelectorAll(".tab-panel");
    const pageTitleLabel = document.getElementById("page-title-label");
    const sysStatusBadge = document.getElementById("system-status-badge");
    const sysStatusText = document.getElementById("system-status-text");

    // Dashboard elements
    const statScans = document.getElementById("stat-scans");
    const statMalware = document.getElementById("stat-malware");
    const statAvgRisk = document.getElementById("stat-avg-risk");
    const statRules = document.getElementById("stat-rules");
    const threatsList = document.getElementById("dashboard-threats-list");

    // Scanner elements
    const presetGrid = document.getElementById("preset-apps-grid");
    const manifestInput = document.getElementById("manifest-xml-input");
    const runScanBtn = document.getElementById("run-scan-btn");
    const clearScanBtn = document.getElementById("clear-scan-btn");
    const scanLoader = document.getElementById("scan-loader");
    const loaderTitle = document.getElementById("loader-title");
    const loaderTerm = document.getElementById("loader-terminal-log");
    const scanResultsPanel = document.getElementById("scan-results-dashboard");
    const riskScoreVal = document.getElementById("risk-score-value");
    const riskBadge = document.getElementById("risk-classification-badge");
    const appDisplayName = document.getElementById("app-display-name");
    const appDisplayPackage = document.getElementById("app-display-package");
    const appDisplayDev = document.getElementById("app-display-dev");
    const threatDesc = document.getElementById("threat-classification-description");
    const ruleMatchesCount = document.getElementById("rule-matches-count");
    const scannedPermsCount = document.getElementById("scanned-perms-count");
    const btnShowRules = document.getElementById("btn-show-rules");
    const btnShowPerms = document.getElementById("btn-show-perms");
    const panelRules = document.getElementById("panel-rules-matches");
    const panelPerms = document.getElementById("panel-perms-breakdown");
    const findingsContainer = document.getElementById("scan-findings-container");
    const permissionsContainer = document.getElementById("scan-permissions-container");

    // Permission Analyzer elements
    const analyzerSearch = document.getElementById("permission-search-input");
    const analyzerDirectory = document.getElementById("analyzer-directory-list");

    // ML Visualizer elements
    const mlVectorDisplay = document.getElementById("ml-vector-display");

    // Database elements
    const dbConsoleLog = document.getElementById("db-console-log");
    const dbConsoleQuery = document.getElementById("db-console-query-input");
    const dbTableHistoryBody = document.getElementById("db-table-history-body");
    const dbClearHistoryBtn = document.getElementById("db-clear-history-btn");

    // Rule Editor elements
    const ruleRegistryGrid = document.getElementById("rule-registry-cards");
    const btnNewRuleModal = document.getElementById("btn-new-rule-modal");
    const ruleModal = document.getElementById("rule-creation-modal");
    const btnCloseModal = document.getElementById("btn-close-modal");
    const btnCancelModal = document.getElementById("btn-cancel-modal");
    const ruleForm = document.getElementById("rule-creation-form");
    const ruleFormCheckboxes = document.getElementById("rule-form-checkboxes");

    // Client-Server Console elements
    const endpointLog = document.getElementById("endpoint-console-log");
    const endpointClearBtn = document.getElementById("console-clear-btn");

    // Bottom Sheet elements (Mobile Navigation)
    const bottomSheet = document.getElementById("bottom-sheet");
    const bottomSheetContent = document.getElementById("bottom-sheet-content");
    const closeBottomSheetBtn = document.getElementById("close-bottom-sheet");

    // ---------------------------------------------------------
    // 3. TAB NAVIGATION ROUTER & BOTTOM SHEET CONTROLLER
    // ---------------------------------------------------------
    function openBottomSheet() {
        if (!bottomSheet) return;
        bottomSheet.classList.remove("hidden");
        // Force a reflow to trigger transition
        bottomSheet.offsetHeight;
        bottomSheet.classList.remove("opacity-0");
        bottomSheetContent.classList.remove("translate-y-full");
    }

    function closeBottomSheet() {
        if (!bottomSheet) return;
        bottomSheet.classList.add("opacity-0");
        bottomSheetContent.classList.add("translate-y-full");
        setTimeout(() => {
            bottomSheet.classList.add("hidden");
        }, 300);
    }

    if (closeBottomSheetBtn) {
        closeBottomSheetBtn.addEventListener("click", closeBottomSheet);
    }
    if (bottomSheet) {
        bottomSheet.addEventListener("click", (e) => {
            if (e.target === bottomSheet) closeBottomSheet();
        });
    }

    function updateActiveNavStyles(targetTab) {
        navItems.forEach(item => {
            const tabId = item.getAttribute("data-tab");
            const isSidebarItem = item.closest("aside") !== null;
            const isBottomNavItem = item.closest("nav") !== null && item.closest("#bottom-sheet") === null;
            
            if (tabId === targetTab) {
                if (isSidebarItem) {
                    item.className = "flex items-center gap-md px-md py-sm rounded-xl text-primary bg-primary/10 border-l-4 border-primary transition-all text-left w-full";
                } else if (isBottomNavItem) {
                    item.className = "flex flex-col items-center justify-center text-secondary drop-shadow-[0_0_8px_rgba(78,222,163,0.5)] transition-all duration-200";
                    const icon = item.querySelector(".material-symbols-outlined");
                    if (icon) icon.style.fontVariationSettings = "'FILL' 1";
                }
            } else {
                if (isSidebarItem) {
                    item.className = "flex items-center gap-md px-md py-sm rounded-xl text-text-secondary hover:text-text-primary hover:bg-primary/5 transition-all text-left w-full";
                } else if (isBottomNavItem) {
                    if (tabId !== 'more') {
                        item.className = "flex flex-col items-center justify-center text-text-muted hover:text-primary transition-all duration-200";
                        const icon = item.querySelector(".material-symbols-outlined");
                        if (icon) icon.style.fontVariationSettings = "'FILL' 0";
                    }
                }
            }
        });
    }

    function navigateToTab(targetTab) {
        if (targetTab === "more") {
            openBottomSheet();
            return;
        }

        closeBottomSheet();

        // Update active class on nav links
        updateActiveNavStyles(targetTab);

        // Toggle active panels
        tabPanels.forEach(panel => {
            panel.classList.remove("active");
            panel.classList.add("hidden");
            if (panel.id === targetTab) {
                panel.classList.add("active");
                panel.classList.remove("hidden");
            }
        });

        // Set Header title
        let labelText = "Executive Dashboard";
        if (targetTab === "scanner-tab") labelText = "App Scanner";
        else if (targetTab === "analyzer-tab") labelText = "Permission Analyzer";
        else if (targetTab === "ml-tab") labelText = "ML Classifier";
        else if (targetTab === "database-tab") labelText = "SQLite Database";
        else if (targetTab === "rules-tab") labelText = "Malware Rules Editor";
        else if (targetTab === "console-tab") labelText = "Client-Server Console";

        if (pageTitleLabel) {
            pageTitleLabel.innerText = labelText;
        }

        // Trigger tab-specific refresh if needed
        if (targetTab === "dashboard-tab") {
            renderDashboard();
        } else if (targetTab === "ml-tab") {
            renderMLTrees();
        } else if (targetTab === "database-tab") {
            renderSQLiteTable();
        } else if (targetTab === "rules-tab") {
            renderRulesGrid();
        }
    }

    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const targetTab = item.getAttribute("data-tab");
            navigateToTab(targetTab);
        });
    });

    // Set initial active styles
    updateActiveNavStyles("dashboard-tab");

    // ---------------------------------------------------------
    // 4. EXECUTIVE DASHBOARD RENDERER
    // ---------------------------------------------------------

    function renderDashboard() {
        const history = window.Database.getHistory();
        const rules = window.Database.getRules();

        // Calculate metrics
        const totalScans = history.length;
        const totalMalware = history.filter(h => h.classification === "Malicious").length;
        const avgRisk = totalScans > 0 
            ? Math.round(history.reduce((acc, curr) => acc + curr.risk_score, 0) / totalScans) 
            : 0;

        // Determine average risk descriptor
        let avgRiskLabel = "Low";
        if (avgRisk > 80) avgRiskLabel = "Critical";
        else if (avgRisk > 50) avgRiskLabel = "High";
        else if (avgRisk > 20) avgRiskLabel = "Medium";

        statScans.innerText = totalScans.toLocaleString();
        statMalware.innerText = totalMalware;
        statAvgRisk.innerText = totalScans > 0 ? avgRiskLabel : "None";
        statRules.innerText = rules.length;

        // Render threat alert panel
        threatsList.innerHTML = "";
        const threats = history.filter(h => h.classification === "Malicious" || h.classification === "Suspicious");
        
        if (threats.length === 0) {
            threatsList.innerHTML = `
                <div class="flex flex-col items-center justify-center text-center text-text-muted p-8">
                    <span class="material-symbols-outlined text-[48px] text-secondary mb-xs">check_circle</span>
                    <p class="font-headline-sm text-sm text-text-primary">No threats detected</p>
                    <p class="text-xs text-text-muted mt-1">Your device environment is clean.</p>
                </div>`;
        } else {
            threats.forEach(th => {
                const isMal = th.classification === "Malicious";
                const borderClr = isMal ? "border-error/20 bg-error/5" : "border-accent-amber/20 bg-accent-amber/5";
                const textClr = isMal ? "text-error" : "text-accent-amber";
                const badgeBg = isMal ? "bg-error/20 text-error" : "bg-accent-amber/20 text-accent-amber";
                const icon = isMal ? "bug_report" : "visibility_off";

                const element = document.createElement("div");
                element.className = `p-md flex items-center justify-between hover:bg-primary/5 transition-colors border-b border-outline-variant/15 w-full`;
                element.innerHTML = `
                    <div class="flex items-center gap-md">
                        <div class="w-10 h-10 rounded-lg bg-bg-console border ${isMal ? 'border-error/20 text-error' : 'border-accent-amber/20 text-accent-amber'} flex items-center justify-center">
                            <span class="material-symbols-outlined">${icon}</span>
                        </div>
                        <div>
                            <p class="font-headline-sm text-[14px] text-text-primary font-bold">${th.app_name}</p>
                            <p class="font-body-sm text-body-sm text-text-muted mt-0.5">Score: ${th.risk_score}% | ${th.package_name}</p>
                        </div>
                    </div>
                    <div class="text-right">
                        <span class="block font-label-mono text-xs ${textClr} font-bold">SCORE: ${th.risk_score}</span>
                        <span class="font-label-caps text-[9px] px-2 py-0.5 rounded ${badgeBg} font-bold mt-1 inline-block">${th.classification.toUpperCase()}</span>
                    </div>
                `;
                threatsList.appendChild(element);
            });
        }

        // Draw Chart.js Distribution
        const countSafe = history.filter(h => h.classification === "Safe").length;
        const countMod = history.filter(h => h.classification === "Moderate").length;
        const countSusp = history.filter(h => h.classification === "Suspicious").length;
        const countMal = history.filter(h => h.classification === "Malicious").length;

        // Default mock values if history empty
        let pctSafe = 92;
        let pctSusp = 7;
        let pctMal = 1;

        if (totalScans > 0) {
            pctSafe = Math.round((countSafe / totalScans) * 100);
            pctSusp = Math.round(((countMod + countSusp) / totalScans) * 100);
            pctMal = 100 - pctSafe - pctSusp;
        }

        const safePctEl = document.getElementById("dist-safe-pct");
        const suspPctEl = document.getElementById("dist-suspicious-pct");
        const malPctEl = document.getElementById("dist-malicious-pct");
        if (safePctEl) safePctEl.innerText = `${pctSafe}%`;
        if (suspPctEl) suspPctEl.innerText = `${pctSusp}%`;
        if (malPctEl) malPctEl.innerText = `${pctMal}%`;

        const ctx = document.getElementById("scanDistributionChart").getContext("2d");
        
        if (currentChart) {
            currentChart.destroy();
        }

        currentChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: ["Safe", "Suspicious", "Malicious"],
                datasets: [{
                    data: [pctSafe, pctSusp, pctMal],
                    backgroundColor: [
                        "#4edea3", // secondary (emerald)
                        "#fbbf24", // accent-amber
                        "#ffb4ab"  // error (red)
                    ],
                    borderColor: "transparent",
                    hoverOffset: 10,
                    cutout: "75%"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        enabled: true,
                        backgroundColor: "#1d2026",
                        titleFont: { family: "Outfit", size: 14 },
                        bodyFont: { family: "Inter", size: 12 }
                    }
                },
                animation: {
                    animateScale: true,
                    animateRotate: true
                }
            }
        });
    }

    function initPresets() {
        presetGrid.innerHTML = "";
        
        const presetMapping = {
            "com.whatsapp": { icon: "chat", colorClass: "bg-secondary/10 text-secondary", category: "SOCIAL" },
            "com.freepuzzle.sudoku": { icon: "grid_on", colorClass: "bg-accent-amber/10 text-accent-amber", category: "GAMING" },
            "com.smartmaps.gps": { icon: "map", colorClass: "bg-primary/10 text-primary", category: "UTILITY" },
            "com.helper.torchpro": { icon: "flashlight_on", colorClass: "bg-primary/10 text-primary", category: "UTILITY" },
            "com.android.sys.update": { icon: "settings", colorClass: "bg-error/10 text-error", category: "SYSTEM" },
            "com.sec.backup.audio": { icon: "mic", colorClass: "bg-error/10 text-error", category: "UTILITY" },
            "com.wannacry.ransom": { icon: "lock", colorClass: "bg-error/10 text-error", category: "SECURITY" }
        };

        window.AppScanner.presets.forEach((preset, index) => {
            const mapInfo = presetMapping[preset.packageName] || { icon: "android", colorClass: "bg-primary/10 text-primary", category: "APP" };
            
            const card = document.createElement("button");
            card.type = "button";
            card.className = "preset-card glass-panel p-md rounded-xl flex flex-col items-center justify-center gap-xs hover:border-primary/50 border border-outline-variant/15 transition-colors active:scale-95 text-center w-full";
            card.setAttribute("data-index", index);
            card.innerHTML = `
                <div class="w-12 h-12 rounded-lg ${mapInfo.colorClass} flex items-center justify-center mb-xs mx-auto">
                    <span class="material-symbols-outlined text-[32px]">${mapInfo.icon}</span>
                </div>
                <span class="font-headline-sm text-[14px] font-bold block truncate max-w-full text-text-primary">${preset.name}</span>
                <span class="font-label-caps text-[10px] text-text-muted block mt-1">${mapInfo.category}</span>
            `;
            
            card.addEventListener("click", () => {
                document.querySelectorAll(".preset-card").forEach(c => c.classList.remove("border-primary", "cyber-glow"));
                card.classList.add("border-primary", "cyber-glow");
                manifestInput.value = preset.manifestText;
            });
            presetGrid.appendChild(card);
        });
    }

    runScanBtn.addEventListener("click", () => {
        const xmlContent = manifestInput.value.trim();
        if (!xmlContent) {
            alert("Please paste an AndroidManifest.xml string or select one of the device app presets first!");
            return;
        }

        // Identify App profile
        let appName = "Custom Manifest APK";
        let packageName = "com.custom.app";
        let developerName = "Unknown Self-Sign Entity";

        // Check if matching preset
        const matchedPreset = window.AppScanner.presets.find(p => p.manifestText.trim() === xmlContent);
        if (matchedPreset) {
            appName = matchedPreset.name;
            packageName = matchedPreset.packageName;
            developerName = matchedPreset.developer;
        } else {
            // Regex parse package name
            const pkgRegex = /package=["']([^"']+)["']/i;
            const pkgMatch = xmlContent.match(pkgRegex);
            if (pkgMatch && pkgMatch[1]) {
                packageName = pkgMatch[1];
                const parts = packageName.split('.');
                appName = parts[parts.length - 1];
                appName = appName.charAt(0).toUpperCase() + appName.slice(1) + " App";
            }
        }

        // Reset Results Panel
        scanResultsPanel.style.display = "none";
        scanLoader.style.display = "block";
        loaderTitle.innerText = `Analyzing Manifest: ${appName}`;
        loaderTerm.innerHTML = "";

        // Add network monitor header log
        logNetworkMonitor(`[REQUEST] Initiating threat prediction payload scan for ${packageName}...`);

        // Simulated scanning routines with console ticks
        const logTicks = [
            { text: "Reading manifest file nodes and permissions XML tree...", delay: 0 },
            { text: "Static Analysis: Parsing permissions vector from AndroidManifest.xml...", delay: 300 },
            { text: "Querying database 'malware_detector.db' rules logic...", delay: 600 },
            { text: "Rule-Based Engine: Checking intersections...", delay: 900 },
            { text: "Flask API Endpoint: Sending POST /predict with extracted feature list...", delay: 1200 },
            { text: "Server response received. Classifier ensemble score evaluated...", delay: 1500 },
            { text: "SQLite Database: Recording scan report into scan_history table...", delay: 1700 },
            { text: "Scan completed. Outputting report dashboard.", delay: 1900 }
        ];

        logTicks.forEach(tick => {
            setTimeout(() => {
                const line = document.createElement("div");
                line.style.marginBottom = "3px";
                line.innerHTML = `<span style="color:var(--accent-blue)">[Scanner]</span> ${tick.text}`;
                loaderTerm.appendChild(line);
                loaderTerm.scrollTop = loaderTerm.scrollHeight;
            }, tick.delay);
        });

        // Trigger analysis after logs complete
        setTimeout(() => {
            // 1. Extract permissions
            const permissions = window.AppScanner.parseManifest(xmlContent);
            
            // 2. Rule evaluation
            const ruleResult = window.RuleEngine.analyze(permissions);
            
            // 3. Machine Learning evaluation
            const mlResult = window.MLPredictor.predict(permissions);

            // 4. Hybrid Compilation
            // If rule-based risk triggers high, use rule engine weight, otherwise take ML weight or average.
            // Let's compute hybrid risk score:
            let hybridRiskScore = mlResult.riskScore;
            if (ruleResult.ruleRiskScore > hybridRiskScore) {
                // If a rule specifically highlights critical malware risk, elevate risk score
                hybridRiskScore = Math.max(ruleResult.ruleRiskScore, mlResult.riskScore);
            }

            let hybridClassification = "Safe";
            if (hybridRiskScore > 80) hybridClassification = "Malicious";
            else if (hybridRiskScore > 50) hybridClassification = "Suspicious";
            else if (hybridRiskScore > 20) hybridClassification = "Moderate";

            currentScanData = {
                app_name: appName,
                package_name: packageName,
                risk_score: hybridRiskScore,
                classification: hybridClassification,
                permissions_scanned: permissions,
                matched_rules: ruleResult.matchedRules,
                scan_date: new Date().toISOString().slice(0, 19).replace('T', ' '),
                mlDetails: mlResult,
                ruleDetails: ruleResult
            };

            // 5. Save to Database
            window.Database.addHistoryRecord({
                app_name: currentScanData.app_name,
                package_name: currentScanData.package_name,
                risk_score: currentScanData.risk_score,
                classification: currentScanData.classification,
                permissions_scanned: currentScanData.permissions_scanned,
                matched_rules: currentScanData.matched_rules
            });

            // Update System Health Badge in header
            updateSystemHeaderStatus();

            // Populate Results GUI
            populateScanResults(currentScanData, developerName);

            // Log client-server traffic
            logClientServerNetworkTraffic(currentScanData);

            // Hide loader & show results
            scanLoader.style.display = "none";
            scanResultsPanel.style.display = "block";

            // Update tree displays immediately in background
            renderMLTrees();

        }, 2000);
    });

    clearScanBtn.addEventListener("click", () => {
        manifestInput.value = "";
        document.querySelectorAll(".preset-card").forEach(c => c.classList.remove("active-preset"));
        scanResultsPanel.style.display = "none";
        scanLoader.style.display = "none";
        currentScanData = null;
    });

    function populateScanResults(data, developerName) {
        const score = data.risk_score;
        riskScoreVal.innerText = `${score}%`;

        // Speedometer gauge half-circle animation
        const activeDial = document.getElementById("active-gauge-dial");
        if (activeDial) {
            // Calculate rotation: 0% -> -180deg, 100% -> 0deg
            const rotation = (score / 100) * 180 - 180;
            activeDial.style.transform = `rotate(${rotation}deg)`;
            
            // Set dial border color
            activeDial.className = "w-64 h-64 border-[16px] rounded-full absolute top-0 speedometer-clip transition-all duration-1000";
            if (data.classification === "Safe") {
                activeDial.classList.add("border-secondary");
            } else if (data.classification === "Moderate") {
                activeDial.classList.add("border-accent-amber");
            } else if (data.classification === "Suspicious") {
                activeDial.classList.add("border-accent-orange");
            } else {
                activeDial.classList.add("border-error");
            }
        }

        // Badge and score color update
        riskBadge.innerText = data.classification.toUpperCase() + " RISK";
        riskBadge.className = "font-label-caps tracking-widest mt-1 text-xs font-bold";
        
        if (data.classification === "Safe") {
            riskBadge.classList.add("text-secondary");
            riskScoreVal.className = "font-display-lg text-[42px] lg:text-[48px] text-secondary font-extrabold leading-none";
        } else if (data.classification === "Moderate") {
            riskBadge.classList.add("text-accent-amber");
            riskScoreVal.className = "font-display-lg text-[42px] lg:text-[48px] text-accent-amber font-extrabold leading-none";
        } else if (data.classification === "Suspicious") {
            riskBadge.classList.add("text-accent-orange");
            riskScoreVal.className = "font-display-lg text-[42px] lg:text-[48px] text-accent-orange font-extrabold leading-none";
        } else {
            riskBadge.classList.add("text-error");
            riskScoreVal.className = "font-display-lg text-[42px] lg:text-[48px] text-error font-extrabold leading-none";
        }

        // Details label
        appDisplayName.innerText = data.app_name;
        appDisplayPackage.innerText = data.package_name;
        appDisplayDev.innerText = developerName;

        // Construct narrative report description
        let descHtml = "";
        if (data.classification === "Safe") {
            descHtml = `Application exhibits normal operational parameters. Permission requests are aligned with standard utility services and no high-risk malicious rules were triggered.`;
        } else if (data.classification === "Moderate") {
            descHtml = `App requests capabilities that could trace location or access device details. Verify if offline mapping/tracking features are expected for this developer profile.`;
        } else if (data.classification === "Suspicious") {
            descHtml = `Warning: App requests advanced capabilities including drawing system overlays or background persistence. System classifies this package as suspicious. Monitor background resource logs closely.`;
        } else if (data.classification === "Malicious") {
            descHtml = `<strong style="color:var(--accent-red)">CRITICAL THREAT DETECTED:</strong> This package intercepts banking 2FA credentials or runs overlay components. Recommend immediate uninstallation to prevent identity theft.`;
        }
        threatDesc.innerHTML = descHtml;

        // Rule matches count
        ruleMatchesCount.innerText = data.matched_rules.length;
        scannedPermsCount.innerText = data.permissions_scanned.length;

        // Populate Findings list (Static Rule matches)
        findingsContainer.innerHTML = "";
        if (data.ruleDetails.findings.length === 0) {
            findingsContainer.innerHTML = `
                <div class="flex flex-col items-center justify-center text-center text-text-muted p-8">
                    <span class="material-symbols-outlined text-[32px] text-secondary mb-xs">shield</span>
                    <p class="font-headline-sm text-sm text-text-primary">No malware rules matched this package structure.</p>
                </div>`;
        } else {
            data.ruleDetails.findings.forEach(find => {
                const element = document.createElement("div");
                const isExtreme = find.weight > 60;
                
                element.className = `glass-panel p-md rounded-xl flex items-start gap-md border-l-4 ${isExtreme ? 'border-l-error bg-error/5' : 'border-l-accent-amber bg-accent-amber/5'}`;
                const icon = isExtreme ? "error" : "warning";
                const triggersHtml = find.triggerPermissions.map(p => `<span class="font-label-mono text-[9px] bg-bg-console border border-outline-variant/30 text-text-secondary px-2 py-0.5 rounded">${p}</span>`).join(" ");

                element.innerHTML = `
                    <span class="material-symbols-outlined ${isExtreme ? 'text-error' : 'text-accent-amber'} mt-1">${icon}</span>
                    <div>
                        <h4 class="font-headline-sm text-[15px] text-text-primary font-bold">Rule Match: ${find.name} (Weight: ${find.weight})</h4>
                        <p class="font-body-sm text-text-muted mt-1">${find.description}</p>
                        <div class="flex flex-wrap gap-1.5 mt-2">
                            ${triggersHtml}
                        </div>
                    </div>
                `;
                findingsContainer.appendChild(element);
            });
        }

        // Populate Permissions breakdown list
        permissionsContainer.innerHTML = "";
        if (data.permissions_scanned.length === 0) {
            permissionsContainer.innerHTML = `
                <div class="flex flex-col items-center justify-center text-center text-text-muted p-8">
                    <p class="font-headline-sm text-sm text-text-primary">No permissions requested in this app package.</p>
                </div>`;
        } else {
            const breakdowns = window.AppScanner.getPermissionBreakdown(data.permissions_scanned);
            breakdowns.forEach(bd => {
                const isDang = bd.category === "Dangerous";
                const badgeClass = isDang ? "bg-error/15 text-error border-error/20" : "bg-primary/15 text-primary border-primary/20";

                const element = document.createElement("div");
                element.className = "glass-panel p-md rounded-xl flex justify-between items-center gap-md border border-outline-variant/15";
                element.innerHTML = `
                    <div class="flex flex-col gap-1 text-left">
                        <span class="font-bold text-[14px] text-text-primary">${bd.name}</span>
                        <span class="font-label-mono text-[10px] text-text-muted">${bd.permission}</span>
                        <span class="text-xs text-text-secondary leading-relaxed mt-1">${bd.desc}</span>
                    </div>
                    <span class="font-label-caps text-[10px] px-2.5 py-1 border rounded-full font-bold ${badgeClass} self-start flex-shrink-0">${bd.category}</span>
                `;
                permissionsContainer.appendChild(element);
            });
        }
    }

    // Toggle sub tabs on results
    btnShowRules.addEventListener("click", () => {
        btnShowRules.className = "flex-1 py-2 rounded-lg bg-surface-container text-text-primary font-label-caps text-label-caps transition-all cursor-pointer focus:outline-none";
        btnShowPerms.className = "flex-1 py-2 rounded-lg text-text-muted font-label-caps text-label-caps hover:text-text-primary transition-all cursor-pointer focus:outline-none";
        panelRules.classList.remove("hidden");
        panelPerms.classList.add("hidden");
    });

    btnShowPerms.addEventListener("click", () => {
        btnShowPerms.className = "flex-1 py-2 rounded-lg bg-surface-container text-text-primary font-label-caps text-label-caps transition-all cursor-pointer focus:outline-none";
        btnShowRules.className = "flex-1 py-2 rounded-lg text-text-muted font-label-caps text-label-caps hover:text-text-primary transition-all cursor-pointer focus:outline-none";
        panelRules.classList.add("hidden");
        panelPerms.classList.remove("hidden");
    });

    function updateSystemHeaderStatus() {
        const history = window.Database.getHistory();
        const badge = document.getElementById("system-status-badge");
        const text = document.getElementById("system-status-text");
        const dot = document.getElementById("system-status-dot");
        const pGlow = badge ? badge.querySelector(".pulse-glow") : null;
        
        const cleanBanner = document.getElementById("system-status-clean-badge");

        const hasMalicious = history.length > 0 && history[0].classification === "Malicious";

        if (hasMalicious) {
            if (badge) {
                badge.className = "glass-card rounded-full px-4 py-1.5 flex items-center gap-2 border-error/20 bg-error/5 text-error";
            }
            if (text) text.innerText = "Threat Active";
            if (dot) {
                dot.className = "relative inline-flex rounded-full h-2.5 w-2.5 bg-error";
            }
            if (pGlow) {
                pGlow.className = "pulse-glow absolute inline-flex h-full w-full rounded-full bg-error opacity-75";
            }
            if (cleanBanner) {
                cleanBanner.innerText = "THREAT ACTIVE";
                cleanBanner.className = "font-label-caps text-label-caps text-error bg-error/10 px-2 py-1 rounded font-bold";
            }
        } else {
            if (badge) {
                badge.className = "glass-card rounded-full px-4 py-1.5 flex items-center gap-2 border-secondary/20 bg-secondary/5 text-secondary";
            }
            if (text) text.innerText = "System Secure";
            if (dot) {
                dot.className = "relative inline-flex rounded-full h-2.5 w-2.5 bg-secondary";
            }
            if (pGlow) {
                pGlow.className = "pulse-glow absolute inline-flex h-full w-full rounded-full bg-secondary opacity-75";
            }
            if (cleanBanner) {
                cleanBanner.innerText = "100% CLEAN";
                cleanBanner.className = "font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-1 rounded font-bold";
            }
        }
    }

    // ---------------------------------------------------------
    // 6. PERMISSION ANALYZER DIRECTORY
    // ---------------------------------------------------------
    function renderPermissionDirectory(query = "") {
        analyzerDirectory.innerHTML = "";
        const meta = window.AppScanner.permissionMetadata;
        
        let count = 0;
        for (const [permId, detail] of Object.entries(meta)) {
            // Filter match
            const matchQuery = permId.toLowerCase().includes(query.toLowerCase()) || 
                               detail.name.toLowerCase().includes(query.toLowerCase()) || 
                               detail.desc.toLowerCase().includes(query.toLowerCase());
            
            if (!matchQuery) continue;

            const isDang = detail.category === "Dangerous";
            const badgeClass = isDang ? "bg-error/15 text-error border-error/20" : "bg-primary/15 text-primary border-primary/20";

            const element = document.createElement("div");
            element.className = "glass-panel p-md rounded-xl flex justify-between items-center gap-md border border-outline-variant/15 text-left";
            element.innerHTML = `
                <div class="flex flex-col gap-1">
                    <span class="font-bold text-[14px] text-text-primary">${detail.name}</span>
                    <span class="font-label-mono text-[10px] text-text-muted">${permId}</span>
                    <span class="text-xs text-text-secondary leading-relaxed mt-1">${detail.desc}</span>
                </div>
                <span class="font-label-caps text-[10px] px-2.5 py-1 border rounded-full font-bold ${badgeClass} self-start flex-shrink-0">${detail.category}</span>
            `;
            analyzerDirectory.appendChild(element);
            count++;
        }

        if (count === 0) {
            analyzerDirectory.innerHTML = `
                <div class="flex flex-col items-center justify-center text-center text-text-muted p-8">
                    <p class="font-headline-sm text-sm text-text-primary">No indexed permissions match your search query.</p>
                </div>`;
        }
    }

    analyzerSearch.addEventListener("keyup", (e) => {
        renderPermissionDirectory(e.target.value);
    });

    // ---------------------------------------------------------
    // 7. MACHINE LEARNING ENSEMBLE VISUALIZER
    // ---------------------------------------------------------
    function renderMLTrees() {
        // Feature importances horizontal bar chart
        const ftCtx = document.getElementById("featureImportanceChart").getContext("2d");
        
        if (featureChart) {
            featureChart.destroy();
        }

        const labels = Object.keys(window.MLPredictor.featureImportances);
        const values = Object.values(window.MLPredictor.featureImportances);

        featureChart = new Chart(ftCtx, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Random Forest Gini Importance Weight",
                    data: values,
                    backgroundColor: "rgba(56, 189, 248, 0.45)",
                    borderColor: "#8ed5ff",
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(ctx) { return `Importance: ${Math.round(ctx.raw * 100)}%`; }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255,255,255,0.03)" },
                        ticks: { color: "#9ca3af" }
                    },
                    y: {
                        grid: { display: false },
                        ticks: {
                            color: "#f3f4f6",
                            font: { family: "Fira Code", size: 10 }
                        }
                    }
                }
            }
        });

        // Set active vector display
        mlVectorDisplay.innerHTML = "";
        const testPermissions = currentScanData ? currentScanData.permissions_scanned : [];
        const vector = window.MLPredictor.extractFeatureVector(testPermissions);

        window.MLPredictor.features.forEach(feat => {
            const active = vector[feat.name] === 1;
            const badge = document.createElement("span");
            
            badge.className = active 
                ? "px-2.5 py-1 text-xs font-label-mono bg-primary/15 border border-primary/30 text-primary rounded-lg font-semibold"
                : "px-2.5 py-1 text-xs font-label-mono bg-bg-console border border-outline-variant/30 text-text-muted rounded-lg";
            badge.innerText = `${feat.name}: ${active ? '1' : '0'}`;
            
            mlVectorDisplay.appendChild(badge);
        });

        // Generate Tree structures visually
        const details = currentScanData ? currentScanData.mlDetails.treeDetails : null;

        renderTreeStructure("tree-1-structure", window.MLPredictor.trees[0].root, details ? details[1] : null);
        renderTreeStructure("tree-2-structure", window.MLPredictor.trees[1].root, details ? details[2] : null);
        renderTreeStructure("tree-3-structure", window.MLPredictor.trees[2].root, details ? details[3] : null);

        // Update predictions outcomes tags
        document.getElementById("t1-tree-result").innerText = details ? `Predict: ${Math.round(details[1].prediction*100)}%` : "Idle";
        document.getElementById("t2-tree-result").innerText = details ? `Predict: ${Math.round(details[2].prediction*100)}%` : "Idle";
        document.getElementById("t3-tree-result").innerText = details ? `Predict: ${Math.round(details[3].prediction*100)}%` : "Idle";
    }

    function renderTreeStructure(containerId, rootNode, traceDetails) {
        const container = document.getElementById(containerId);
        container.innerHTML = "";
        
        const path = traceDetails ? traceDetails.path : [];

        function buildNodeHtml(node) {
            const isTraversed = path.includes(node.id);
            const activeClass = isTraversed ? "active-path" : "";
            const activeLabelClass = isTraversed ? "active-label" : "";

            if (node.leaf) {
                const isMal = node.prediction > 0.5;
                const leafClass = isTraversed ? `active-leaf ${isMal ? 'malicious-leaf' : ''}` : '';
                return `
                    <div class="tree-node ${activeClass}">
                        <span class="tree-label tree-leaf-label ${leafClass}">
                            🍃 Leaf: ${Math.round(node.prediction * 100)}% (${isMal ? 'Threat' : 'Safe'})
                        </span>
                    </div>
                `;
            }

            // Normal node
            const featureMeta = window.MLPredictor.features.find(f => f.name === node.feature);
            const label = featureMeta ? featureMeta.label : node.feature;

            return `
                <div class="tree-node ${activeClass}">
                    <span class="tree-label ${activeLabelClass}">
                        ❓ Ask: ${label}?
                    </span>
                    <div style="margin-top: 6px; font-size:9px; color: #6b7280; padding-left: 10px;">
                        <div>✔️ Yes</div>
                        ${buildNodeHtml(node.yes)}
                        <div style="margin-top:4px;">❌ No</div>
                        ${buildNodeHtml(node.no)}
                    </div>
                </div>
            `;
        }

        container.innerHTML = buildNodeHtml(rootNode);
    }

    // ---------------------------------------------------------
    // 8. SQLITE DATABASE CONSOLE INTERPRETER
    // ---------------------------------------------------------
    function renderSQLiteTable() {
        dbTableHistoryBody.innerHTML = "";
        const history = window.Database.getHistory();
        
        if (history.length === 0) {
            dbTableHistoryBody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-text-muted p-8">
                        No records logged in SQLite database scan_history table.
                    </td>
                </tr>`;
        } else {
            history.forEach(rec => {
                const tr = document.createElement("tr");
                tr.className = "hover:bg-bg-surface/20 transition-colors";
                let badgeClass = "bg-secondary/15 text-secondary border-secondary/20";
                if (rec.classification === "Malicious") badgeClass = "bg-error/15 text-error border-error/20";
                else if (rec.classification === "Suspicious") badgeClass = "bg-accent-orange/15 text-accent-orange border-accent-orange/20";
                else if (rec.classification === "Moderate") badgeClass = "bg-accent-amber/15 text-accent-amber border-accent-amber/20";

                tr.innerHTML = `
                    <td class="p-md font-label-mono text-xs text-text-muted"><code>${rec.id}</code></td>
                    <td class="p-md text-text-primary font-bold">${rec.app_name}</td>
                    <td class="p-md font-label-mono text-xs text-text-muted"><code>${rec.package_name}</code></td>
                    <td class="p-md text-primary font-bold">${rec.risk_score}%</td>
                    <td class="p-md">
                        <span class="font-label-caps text-[9px] px-2.5 py-0.5 border rounded-full font-bold ${badgeClass}">${rec.classification.toUpperCase()}</span>
                    </td>
                    <td class="p-md text-text-muted text-xs">${rec.scan_date}</td>
                `;
                dbTableHistoryBody.appendChild(tr);
            });
        }
    }

    dbConsoleQuery.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            const query = dbConsoleQuery.value.trim();
            if (!query) return;

            // Log query to terminal
            const cmdLine = document.createElement("div");
            cmdLine.innerHTML = `<span class="text-primary font-bold">sqlite&gt;</span> ${query}`;
            dbConsoleLog.appendChild(cmdLine);

            dbConsoleQuery.value = "";

            // Execute mock query
            const res = window.Database.executeSQL(query);
            const resDiv = document.createElement("div");
            resDiv.className = "mt-1 mb-3";

            if (res.success) {
                if (res.type === 'SELECT') {
                    if (res.rowCount === 0) {
                        resDiv.innerHTML = `<span class="text-text-muted">Empty set (0.00 sec)</span>`;
                    } else {
                        // Render grid
                        let tableHtml = `<table class="w-full border-collapse border border-outline-variant/30 text-left text-xs mt-2"><thead><tr>`;
                        res.columns.forEach(col => {
                            tableHtml += `<th class="border border-outline-variant/30 px-3 py-1.5 bg-bg-surface text-primary text-xs font-bold">${col}</th>`;
                        });
                        tableHtml += `</tr></thead><tbody>`;

                        res.rows.forEach(row => {
                            tableHtml += `<tr class="hover:bg-bg-surface/20">`;
                            res.columns.forEach(col => {
                                let val = row[col];
                                if (typeof val === 'object') val = JSON.stringify(val);
                                tableHtml += `<td class="border border-outline-variant/30 px-3 py-1 text-slate-300">${val === undefined ? 'NULL' : val}</td>`;
                            });
                            tableHtml += `</tr>`;
                        });

                        tableHtml += `</tbody></table>`;
                        tableHtml += `<div class="text-secondary text-[11px] font-bold mt-1.5">${res.rowCount} row(s) in set.</div>`;
                        resDiv.innerHTML = tableHtml;
                    }
                } else {
                    resDiv.innerHTML = `<span class="text-secondary font-bold">${res.message}</span>`;
                }
            } else {
                resDiv.innerHTML = `<span class="text-error font-bold">${res.message}</span>`;
            }

            dbConsoleLog.appendChild(resDiv);
            dbConsoleLog.scrollTop = dbConsoleLog.scrollHeight;

            // Trigger visual refresh of tabs
            renderSQLiteTable();
            renderRulesGrid();
            renderDashboard();
        }
    });

    dbClearHistoryBtn.addEventListener("click", () => {
        if (confirm("Are you sure you want to run SQLite DELETE query to purge the scan_history table?")) {
            window.Database.clearHistory();
            renderSQLiteTable();
            renderDashboard();
            updateSystemHeaderStatus();
            
            // Console audit log
            const logLine = document.createElement("div");
            logLine.innerHTML = `<span class="text-accent-amber font-bold">[SQLite System Audit]</span> Table scan_history cleared successfully.`;
            dbConsoleLog.appendChild(logLine);
            dbConsoleLog.scrollTop = dbConsoleLog.scrollHeight;
        }
    });

    // ---------------------------------------------------------
    // 9. MALWARE RULE REGISTRY
    // ---------------------------------------------------------
    function renderRulesGrid() {
        ruleRegistryGrid.innerHTML = "";
        const rules = window.Database.getRules();

        rules.forEach(rule => {
            const card = document.createElement("div");
            card.className = "rule-card bg-bg-surface border border-outline-variant/15 rounded-2xl p-lg flex flex-col justify-between gap-md hover:border-primary/50 transition-all shadow-md text-left";
            card.setAttribute("data-id", rule.id);

            const permTags = rule.permissions.map(p => `<span class="font-label-mono text-[9px] bg-bg-console border border-outline-variant/30 text-primary px-2 py-0.5 rounded">${p}</span>`).join(" ");

            card.innerHTML = `
                <div class="flex flex-col gap-2">
                    <div class="flex justify-between items-start gap-2">
                        <span class="font-bold text-[15px] text-text-primary flex items-center gap-1">
                            <span class="material-symbols-outlined text-[18px] text-primary" style="font-variation-settings: 'FILL' 1;">gavel</span>
                            ${rule.rule_name}
                        </span>
                        <span class="font-label-caps text-[10px] bg-accent-amber/15 text-accent-amber border border-accent-amber/20 px-2 py-0.5 rounded font-bold">Weight: ${rule.risk_weight}</span>
                    </div>
                    <p class="text-xs text-text-secondary leading-relaxed">${rule.description}</p>
                </div>
                <div>
                    <div class="flex flex-wrap gap-1.5 my-3">
                        ${permTags}
                    </div>
                    <div class="flex justify-end gap-3 border-t border-outline-variant/15 pt-2">
                        <button class="rule-action-btn rule-action-edit text-xs text-text-muted hover:text-primary transition-colors flex items-center gap-1 cursor-pointer">
                            <span class="material-symbols-outlined text-[16px]">edit</span> Edit
                        </button>
                        <button class="rule-action-btn rule-action-delete text-xs text-text-muted hover:text-error transition-colors flex items-center gap-1 cursor-pointer">
                            <span class="material-symbols-outlined text-[16px]">delete</span> Delete
                        </button>
                    </div>
                </div>
            `;

            // Delete event handler
            card.querySelector(".rule-action-delete").addEventListener("click", () => {
                if (confirm(`Run SQLite query: DELETE FROM malware_rules WHERE id = ${rule.id}?`)) {
                    window.Database.deleteRule(rule.id);
                    renderRulesGrid();
                    renderDashboard();
                    
                    // Log SQL to terminal
                    logNetworkMonitor(`[SQL Database TRANSACTION] Query run: DELETE FROM malware_rules WHERE id = ${rule.id}`);
                }
            });

            // Edit event handler
            card.querySelector(".rule-action-edit").addEventListener("click", () => {
                openRuleModal(rule);
            });

            ruleRegistryGrid.appendChild(card);
        });
    }

    btnNewRuleModal.addEventListener("click", () => {
        openRuleModal();
    });

    btnCloseModal.addEventListener("click", closeRuleModal);
    btnCancelModal.addEventListener("click", closeRuleModal);

    function openRuleModal(rule = null) {
        // Load checkboxes dynamically
        ruleFormCheckboxes.innerHTML = "";
        for (const [permId, detail] of Object.entries(window.AppScanner.permissionMetadata)) {
            const div = document.createElement("div");
            div.className = "flex items-center gap-2";
            div.innerHTML = `
                <input type="checkbox" id="chk-${permId}" value="${permId}" class="rounded border-outline-variant/30 bg-bg-console text-primary focus:ring-primary w-4 h-4">
                <label for="chk-${permId}" class="text-xs text-text-secondary select-none cursor-pointer">${detail.name}</label>
            `;
            ruleFormCheckboxes.appendChild(div);
        }

        // Fill form fields
        if (rule) {
            document.getElementById("modal-form-title").innerText = "Edit Android Malware Rule";
            document.getElementById("rule-form-id").value = rule.id;
            document.getElementById("rule-form-name").value = rule.rule_name;
            document.getElementById("rule-form-weight").value = rule.risk_weight;
            document.getElementById("rule-form-desc").value = rule.description;
            
            // Pre-check permissions
            rule.permissions.forEach(p => {
                const chk = document.getElementById(`chk-${p}`);
                if (chk) chk.checked = true;
            });
        } else {
            document.getElementById("modal-form-title").innerText = "Create Android Malware Rule";
            document.getElementById("rule-form-id").value = "";
            ruleForm.reset();
        }

        ruleModal.classList.remove("hidden");
        ruleModal.classList.add("flex");
    }

    function closeRuleModal() {
        ruleModal.classList.add("hidden");
        ruleModal.classList.remove("flex");
    }

    ruleForm.addEventListener("submit", (e) => {
        e.preventDefault();

        const id = document.getElementById("rule-form-id").value;
        const ruleName = document.getElementById("rule-form-name").value.trim().replace(/\s+/g, '_');
        const weight = parseInt(document.getElementById("rule-form-weight").value);
        const description = document.getElementById("rule-form-desc").value.trim();

        // Get checked permissions
        const checkedPerms = [];
        ruleFormCheckboxes.querySelectorAll("input[type=checkbox]:checked").forEach(chk => {
            checkedPerms.push(chk.value);
        });

        if (checkedPerms.length === 0) {
            alert("Please select at least one trigger permission for this rule logic.");
            return;
        }

        const ruleObj = {
            rule_name: ruleName,
            description: description,
            permissions: checkedPerms,
            risk_weight: weight
        };

        if (id) {
            ruleObj.id = id;
            logNetworkMonitor(`[SQL Database TRANSACTION] Query run: UPDATE malware_rules SET rule_name='${ruleName}', risk_weight=${weight} WHERE id=${id}`);
        } else {
            logNetworkMonitor(`[SQL Database TRANSACTION] Query run: INSERT INTO malware_rules (rule_name, description, permissions, risk_weight) VALUES (...)`);
        }

        // Save to Database
        window.Database.saveRule(ruleObj);

        closeRuleModal();
        renderRulesGrid();
        renderDashboard();
    });

    // ---------------------------------------------------------
    // 10. CLIENT-SERVER ENDPOINT MONITOR LOGS
    // ---------------------------------------------------------
    function logNetworkMonitor(text, category = "sys") {
        const line = document.createElement("div");
        line.className = `term-line ${category}`;
        
        const timestamp = new Date().toISOString().slice(11, 19);
        line.innerHTML = `<span style="color:var(--text-muted)">[${timestamp}]</span> ${text}`;
        
        endpointLog.appendChild(line);
        endpointLog.scrollTop = endpointLog.scrollHeight;
    }

    endpointClearBtn.addEventListener("click", () => {
        endpointLog.innerHTML = `[System] Terminal logs cleared. Waiting for new triggers...<br>`;
    });

    function logClientServerNetworkTraffic(data) {
        const vector = data.mlDetails.vector;
        const featuresJson = JSON.stringify(vector, null, 2);

        // 1. Client permission extraction log
        logNetworkMonitor(`[Client] Extracted ${data.permissions_scanned.length} package permissions from manifest XML payload.`, "info");
        
        // 2. Local rule-checking log
        logNetworkMonitor(`[Client] Querying SQLite for static rules intersections...`, "info");
        if (data.matched_rules.length > 0) {
            logNetworkMonitor(`[Static Rule Engine] MATCHED rules: ${JSON.stringify(data.matched_rules)}`, "warning");
        } else {
            logNetworkMonitor(`[Static Rule Engine] Clean. No static rules intersection matched.`, "success");
        }

        // 3. API payload transmission
        logNetworkMonitor(`[Client API client] Connecting to endpoint http://127.0.0.1:5000/predict ...`, "info");
        logNetworkMonitor(`[Client API client] Sending POST request with JSON header:
<pre style="background:#090d16; color:#a5f3fc; border:1px solid #1e293b; padding:8px; border-radius:6px; margin: 4px 0; max-height: 100px; overflow-y:auto; font-family:var(--font-mono); font-size:10px;">
POST /predict HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/json

{
  "package_name": "${data.package_name}",
  "permissions_vector": ${featuresJson}
}
</pre>`, "info");

        // 4. Server processing
        setTimeout(() => {
            logNetworkMonitor(`[Flask Server 127.0.0.1:5000] Received POST /predict from client agent.`, "sys");
            logNetworkMonitor(`[Flask Server ML Module] Running Random Forest prediction ensemble (Tree count: 3)...`, "sys");
            
            const trOutputs = [];
            for (const [tId, tVal] of Object.entries(data.mlDetails.treeDetails)) {
                trOutputs.push(`Tree ${tId} outcome = ${Math.round(tVal.prediction*100)}% (${tVal.decisionText})`);
            }

            logNetworkMonitor(`[Flask Server ML Module] Ensemble decision paths complete:<br>${trOutputs.join('<br>')}`, "sys");
            logNetworkMonitor(`[Flask Server ML Module] Calculated ensemble malware probability: <strong style="color:var(--accent-blue)">${data.mlDetails.riskScore}%</strong>`, "sys");

            const classificationText = data.mlDetails.classification;
            const classColor = classificationText === 'Malicious' ? 'var(--accent-red)' : (classificationText === 'Suspicious' ? '#f97316' : 'var(--accent-green)');

            logNetworkMonitor(`[Flask Server 127.0.0.1:5000] Returning HTTP status 200 OK. Response body:
<pre style="background:#090d16; color:#a5f3fc; border:1px solid #1e293b; padding:8px; border-radius:6px; margin: 4px 0; font-family:var(--font-mono); font-size:10px;">
{
  "status": "success",
  "data": {
    "malware_probability": ${data.mlDetails.probability},
    "classification": "${classificationText}",
    "risk_score": ${data.mlDetails.riskScore}
  }
}
</pre>`, "sys");

            // 5. Client SQLite transaction log
            logNetworkMonitor(`[Client Response Listener] Payload received from server successfully (Latency: 284ms).`, "success");
            logNetworkMonitor(`[Client SQLite Module] Writing record to local SQLite table:
<span style="color:#fcd34d">INSERT INTO scan_history (app_name, package_name, risk_score, classification, scan_date) VALUES ('${data.app_name}', '${data.package_name}', ${data.risk_score}, '${data.classification}', '${data.scan_date}');</span>`, "info");
            logNetworkMonitor(`[Client UI Controller] Redrawing dashboard graphs. Status updated: <strong style="color:${classColor}">${data.classification}</strong>.`, "success");
        }, 800);
    }

    // ---------------------------------------------------------
    // 11. INITIAL RUNTIME BOOTSTRAPPER
    // ---------------------------------------------------------
    function init() {
        initPresets();
        renderPermissionDirectory();
        renderDashboard();
        updateSystemHeaderStatus();

        // Search input filters
        const scannerSearchInput = document.getElementById("scanner-search-input");
        if (scannerSearchInput) {
            scannerSearchInput.addEventListener("keyup", (e) => {
                const query = e.target.value.toLowerCase();
                document.querySelectorAll("#preset-apps-grid .preset-card").forEach(card => {
                    const name = card.querySelector(".font-headline-sm").innerText.toLowerCase();
                    if (name.includes(query)) {
                        card.classList.remove("hidden");
                        card.classList.add("flex");
                    } else {
                        card.classList.add("hidden");
                        card.classList.remove("flex");
                    }
                });
            });
        }

        // Quarantine click event handler
        const quarantineBtn = document.getElementById("quarantine-btn");
        if (quarantineBtn) {
            quarantineBtn.addEventListener("click", () => {
                if (currentScanData) {
                    alert(`Application ${currentScanData.app_name} (${currentScanData.package_name}) has been simulated quarantined. Stored sandbox access and background permissions have been revoked.`);
                } else {
                    alert("No scanned application selected to quarantine.");
                }
            });
        }
    }

    init();
});
