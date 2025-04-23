document.addEventListener('DOMContentLoaded', function () {
    // Initialize the activity chart when the DOM is fully loaded
    initializeActivityChart();
});

/**
 * Initializes the activity chart with data from the backend
 */
function initializeActivityChart() {
    const ctx = document.getElementById('activityChart').getContext('2d');

    // Check if the canvas element exists
    if (!ctx) {
        console.error('Activity chart canvas not found');
        return;
    }

    // Get data from the data attributes (these will be populated by the template)
    const activityLabels = JSON.parse(document.getElementById('activityChart').getAttribute('data-labels') || '[]');
    const inquiryData = JSON.parse(document.getElementById('activityChart').getAttribute('data-inquiries') || '[]');
    const predictionData = JSON.parse(document.getElementById('activityChart').getAttribute('data-predictions') || '[]');

    // Create the chart
    const activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: activityLabels,
            datasets: [{
                label: 'New Inquiries',
                data: inquiryData,
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderWidth: 2,
                tension: 0.3
            }, {
                label: 'New Predictions',
                data: predictionData,
                borderColor: 'rgba(153, 102, 255, 1)',
                backgroundColor: 'rgba(153, 102, 255, 0.2)',
                borderWidth: 2,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Toggles visibility of patient details (can be used for expandable patient cards)
 * @param {string} patientId - The ID of the patient whose details should be toggled
 */
function togglePatientDetails(patientId) {
    const detailsElement = document.getElementById(`patient-details-${patientId}`);
    if (detailsElement) {
        detailsElement.classList.toggle('expanded');
    }
}

/**
 * Handles form submission for quick actions
 * @param {Event} event - The form submission event
 * @param {string} action - The action being performed
 */
function handleQuickAction(event, action) {
    // Prevent default form submission
    event.preventDefault();

    // Perform action based on the button clicked
    switch (action) {
        case 'new-prediction':
            window.location.href = '/new-prediction';
            break;
        case 'add-patient':
            window.location.href = '/add-patient';
            break;
        case 'messages':
            window.location.href = '/medic-feedback';
            break;
        case 'export-data':
            window.location.href = '/export-data';
            break;
        default:
            console.error('Unknown action:', action);
    }
}

/**
 * Updates dashboard stats via AJAX
 * This function can be called periodically to refresh dashboard data
 */
function refreshDashboardStats() {
    fetch('/api/medic/dashboard-stats')
        .then(response => response.json())
        .then(data => {
            // Update the stats on the page
            document.getElementById('total-patients-count').textContent = data.total_patients;
            document.getElementById('new-inquiries-count').textContent = data.new_inquiries;
            document.getElementById('predictions-made-count').textContent = data.predictions_made;
            document.getElementById('weekly-patients-count').textContent = data.weekly_patients;
        })
        .catch(error => {
            console.error('Error fetching dashboard stats:', error);
        });
}