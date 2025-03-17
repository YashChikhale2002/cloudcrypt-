/**
 * Crypt+ Main JavaScript File
 */

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-hide flash messages after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // File upload form enhancements
    var fileInput = document.getElementById('file');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            var fileName = e.target.files[0].name;
            var fileSize = e.target.files[0].size;
            var fileSizeFormatted = formatFileSize(fileSize);
            
            // Update file info
            var fileInfoElement = document.getElementById('file-info');
            if (fileInfoElement) {
                fileInfoElement.innerHTML = `
                    <div class="alert alert-info">
                        <strong>Selected File:</strong> ${fileName} (${fileSizeFormatted})
                    </div>
                `;
            }
        });
    }

    // Policy selection enhancements
    var policyCheckboxes = document.querySelectorAll('input[name="policies"]');
    if (policyCheckboxes.length > 0) {
        // Add event listener to show summary of selected policies
        policyCheckboxes.forEach(function(checkbox) {
            checkbox.addEventListener('change', updatePolicySelection);
        });
        
        // Initial update
        updatePolicySelection();
    }
});

/**
 * Update the policy selection summary
 */
function updatePolicySelection() {
    var selectedPolicies = document.querySelectorAll('input[name="policies"]:checked');
    var summaryElement = document.getElementById('policy-summary');
    
    if (summaryElement) {
        if (selectedPolicies.length > 0) {
            var policyNames = [];
            selectedPolicies.forEach(function(policy) {
                var label = policy.parentElement.querySelector('label').textContent.trim();
                policyNames.push(label);
            });
            
            summaryElement.innerHTML = `
                <div class="alert alert-success">
                    <strong>${selectedPolicies.length} policies selected:</strong> 
                    ${policyNames.join(', ')}
                </div>
            `;
        } else {
            summaryElement.innerHTML = `
                <div class="alert alert-warning">
                    <strong>No policies selected.</strong> Only you will be able to access this file.
                </div>
            `;
        }
    }
}

/**
 * Format file size in human-readable format
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Show confirmation dialog
 * @param {string} message - Confirmation message
 * @returns {boolean} True if confirmed, false otherwise
 */
function confirmAction(message) {
    return confirm(message || 'Are you sure you want to proceed?');
}

/**
 * Toggle password visibility
 * @param {string} inputId - ID of password input
 * @param {string} iconId - ID of eye icon
 */
function togglePasswordVisibility(inputId, iconId) {
    const passwordInput = document.getElementById(inputId);
    const icon = document.getElementById(iconId);
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        passwordInput.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}