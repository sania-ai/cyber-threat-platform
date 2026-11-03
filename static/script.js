
// ======================================
// 1. GLOBAL CHART THEME
// ======================================

Chart.defaults.color = "#dce8f7";
Chart.defaults.font.family = "Segoe UI, Arial, sans-serif";
Chart.defaults.plugins.legend.labels.color = "#dce8f7";

Chart.defaults.plugins.tooltip.backgroundColor = "#192638";
Chart.defaults.plugins.tooltip.titleColor = "#ffffff";
Chart.defaults.plugins.tooltip.bodyColor = "#dce8f7";
Chart.defaults.plugins.tooltip.borderColor = "#304158";
Chart.defaults.plugins.tooltip.borderWidth = 1;


// ======================================
// 2. CHART REFERENCES
// ======================================

let statusChartInstance = null;
let hostsChartInstance = null;
let trendsChartInstance = null;


// ======================================
// 3. DASHBOARD SUMMARY
// ======================================

async function loadSummary() {

    try {

        const response = await fetch("/api/summary");

        if (!response.ok) {
            throw new Error("Unable to load summary");
        }

        const data = await response.json();

        document.getElementById("totalUrls").textContent =
            data.total_urls ?? 0;

        document.getElementById("onlineUrls").textContent =
            data.online_urls ?? 0;

        document.getElementById("offlineUrls").textContent =
            data.offline_urls ?? 0;

        document.getElementById("uniqueHosts").textContent =
            data.unique_hosts ?? 0;

        createStatusChart(data);

    } catch (error) {

        console.error("Summary error:", error);

    }

}


// ======================================
// 4. URL STATUS DOUGHNUT CHART
// ======================================

function createStatusChart(data) {

    const ctx = document.getElementById("statusChart");

    if (!ctx) return;

    if (statusChartInstance) {
        statusChartInstance.destroy();
    }

    statusChartInstance = new Chart(ctx, {

        type: "doughnut",

        data: {

            labels: ["Online", "Offline"],

            datasets: [{

                data: [
                    data.online_urls ?? 0,
                    data.offline_urls ?? 0
                ],

                backgroundColor: [
                    "#24b9ed",
                    "#ff647c"
                ],

                borderColor: "#192638",
                borderWidth: 4,
                hoverOffset: 8

            }]

        },

        options: {

            responsive: true,
            maintainAspectRatio: false,
            cutout: "62%",

            plugins: {

                legend: {

                    position: "bottom",

                    labels: {
                        color: "#dce8f7",
                        padding: 20,
                        usePointStyle: true,
                        pointStyle: "circle"
                    }

                }

            }

        }

    });

}


// ======================================
// 5. TOP 10 HOSTS CHART
// ======================================

async function loadTopHosts() {

    try {

        const response = await fetch("/api/top-hosts");

        if (!response.ok) {
            throw new Error("Unable to load top hosts");
        }

        const data = await response.json();

        const hosts = data.map(item => item.host);
        const totals = data.map(item => item.total);

        const ctx = document.getElementById("hostsChart");

        if (!ctx) return;

        if (hostsChartInstance) {
            hostsChartInstance.destroy();
        }

        hostsChartInstance = new Chart(ctx, {

            type: "bar",

            data: {

                labels: hosts,

                datasets: [{

                    label: "Number of URLs",
                    data: totals,
                    backgroundColor: "#24b9ed",
                    borderRadius: 5,
                    borderSkipped: false

                }]

            },

            options: {

                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,

                plugins: {

                    legend: {

                        position: "bottom",

                        labels: {
                            color: "#dce8f7"
                        }

                    }

                },

                scales: {

                    x: {

                        beginAtZero: true,

                        ticks: {
                            color: "#9baabd"
                        },

                        grid: {
                            color: "rgba(255,255,255,0.07)"
                        }

                    },

                    y: {

                        ticks: {
                            color: "#dce8f7"
                        },

                        grid: {
                            display: false
                        }

                    }

                }

            }

        });

    } catch (error) {

        console.error("Top hosts error:", error);

    }

}


// ======================================
// 6. THREAT INTELLIGENCE RECORDS
// ======================================

let currentPage = 1;

const recordsPerPage = 10;


async function loadRecords() {

    const search =
        document.getElementById("searchInput").value.trim();

    const status =
        document.getElementById("statusFilter").value;

    const risk =
        document.getElementById("riskFilter").value;

    const params = new URLSearchParams({

        search: search,
        status: status,
        risk: risk,
        page: currentPage,
        per_page: recordsPerPage

    });

    const table = document.getElementById("recordsTable");

    try {

        table.textContent = "";

        const response = await fetch(`/api/urls?${params}`);

        if (!response.ok) {
            throw new Error("Could not load records");
        }

        const data = await response.json();

        if (!data.records || data.records.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 6;
            cell.textContent = "No records found.";

            row.appendChild(cell);
            table.appendChild(row);

        }

        (data.records || []).forEach(record => {

            const row = document.createElement("tr");

            const values = [

                record.url,
                record.host,
                record.url_status,
                record.threat,
                record.risk_level,
                record.date_added

            ];

            values.forEach((value, index) => {

                const cell = document.createElement("td");

                cell.textContent = value || "N/A";

                // ONLINE / OFFLINE STATUS BADGES
                if (index === 2) {

                    const badge = document.createElement("span");

                    badge.classList.add("status-badge");

                    const normalizedStatus =
                        String(value || "").toLowerCase();

                    if (normalizedStatus === "online") {

                        badge.classList.add("status-online");
                        badge.textContent = "● Online";

                    } else if (normalizedStatus === "offline") {

                        badge.classList.add("status-offline");
                        badge.textContent = "● Offline";

                    } else {

                        badge.classList.add("status-unknown");
                        badge.textContent = value || "Unknown";

                    }

                    cell.textContent = "";
                    cell.appendChild(badge);

                }

                // RISK LEVEL STYLING
                if (index === 4) {

                    const normalizedRisk =
                        String(value || "").toLowerCase();

                    if (normalizedRisk === "high") {

                        cell.classList.add("risk-high");

                    } else if (normalizedRisk === "medium") {

                        cell.classList.add("risk-medium");

                    } else {

                        cell.classList.add("risk-unclassified");

                    }

                }

                row.appendChild(cell);

            });

            table.appendChild(row);

        });


        // PAGINATION INFORMATION

        const totalPages = data.total_pages ?? 0;

        document.getElementById("pageInfo").textContent =
            `Page ${data.current_page ?? currentPage} of ${totalPages}`;

        document.getElementById("previousButton").disabled =
            currentPage <= 1 || totalPages === 0;

        document.getElementById("nextButton").disabled =
            currentPage >= totalPages || totalPages === 0;

    } catch (error) {

        console.error("Records error:", error);

        table.textContent = "";

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;

        cell.textContent =
            "Unable to load records. Please try again.";

        row.appendChild(cell);
        table.appendChild(row);

    }

}


// ======================================
// 7. SEARCH BUTTON
// ======================================

document.getElementById("searchButton").addEventListener("click", () => {

    currentPage = 1;
    loadRecords();

});


// ======================================
// 8. SEARCH USING ENTER KEY
// ======================================

document.getElementById("searchInput").addEventListener("keydown", event => {

    if (event.key === "Enter") {

        currentPage = 1;
        loadRecords();

    }

});


// ======================================
// 9. STATUS FILTER
// ======================================

document.getElementById("statusFilter").addEventListener("change", () => {

    currentPage = 1;
    loadRecords();

});


// ======================================
// 10. RISK FILTER
// ======================================

document.getElementById("riskFilter").addEventListener("change", () => {

    currentPage = 1;
    loadRecords();

});


// ======================================
// 11. PREVIOUS PAGE
// ======================================

document.getElementById("previousButton").addEventListener("click", () => {

    if (currentPage > 1) {

        currentPage--;
        loadRecords();

    }

});


// ======================================
// 12. NEXT PAGE
// ======================================

document.getElementById("nextButton").addEventListener("click", () => {

    currentPage++;
    loadRecords();

});


// ======================================
// 13. URL THREAT TRENDS
// ======================================

async function loadTrends() {

    try {

        const response = await fetch("/api/trends");

        if (!response.ok) {
            throw new Error("Unable to load trends");
        }

        const data = await response.json();

        const dates = data.map(item => item.date);
        const totals = data.map(item => item.total);

        const ctx = document.getElementById("trendsChart");

        if (!ctx) return;

        if (trendsChartInstance) {
            trendsChartInstance.destroy();
        }

        trendsChartInstance = new Chart(ctx, {

            type: "line",

            data: {

                labels: dates,

                datasets: [{

                    label: "Malicious URLs Added",
                    data: totals,
                    borderColor: "#24b9ed",
                    backgroundColor: "rgba(36, 185, 237, 0.15)",
                    borderWidth: 3,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 4,
                    pointBackgroundColor: "#24b9ed",
                    pointBorderColor: "#ffffff",
                    pointBorderWidth: 1

                }]

            },

            options: {

                responsive: true,
                maintainAspectRatio: false,

                interaction: {
                    intersect: false,
                    mode: "index"
                },

                plugins: {

                    legend: {

                        position: "bottom",

                        labels: {
                            color: "#dce8f7",
                            padding: 18
                        }

                    }

                },

                scales: {

                    x: {

                        ticks: {
                            color: "#9baabd"
                        },

                        grid: {
                            color: "rgba(255,255,255,0.06)"
                        }

                    },

                    y: {

                        beginAtZero: true,

                        ticks: {
                            color: "#9baabd"
                        },

                        grid: {
                            color: "rgba(255,255,255,0.07)"
                        }

                    }

                }

            }

        });

    } catch (error) {

        console.error("Trends chart error:", error);

    }

}


// ======================================
// 14. SIDEBAR NAVIGATION
// ======================================

function setupSidebarNavigation() {

    const navLinks = document.querySelectorAll(".nav-link");

    navLinks.forEach(link => {

        link.addEventListener("click", () => {

            navLinks.forEach(item => {
                item.classList.remove("active");
            });

            link.classList.add("active");

        });

    });

}


// ======================================
// 15. START DASHBOARD
// ======================================

document.addEventListener("DOMContentLoaded", () => {

    loadSummary();

    loadTopHosts();

    loadRecords();

    loadTrends();

    setupSidebarNavigation();

});
