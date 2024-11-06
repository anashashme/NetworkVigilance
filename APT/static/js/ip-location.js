        // Function to fetch IP details
        function fetchIpDetails() {
            const ip = document.getElementById('ip-input').value;
            const url = `https://api.iplocation.net/?ip=${ip}&format=json`;

            fetch(url)
                .then(response => response.json())
                .then(data => {
                    document.getElementById('ipv4').textContent = data.ip || "N/A";
                    document.getElementById('ip-location').textContent = data.country_name || "N/A";
                    document.getElementById('isp').textContent = data.isp || "N/A";
                    document.getElementById('proxy').textContent = data.response_code === "200" ? "No" : "Yes";
                    document.getElementById('platform').textContent = "N/A"; // Add platform detection logic if needed
                    document.getElementById('ipv6').textContent = data.ip_version === 6 ? data.ip : "N/A";
                    document.getElementById('country-code').textContent = data.country_code2 || "N/A";
                    document.getElementById('ip-number').textContent = data.ip_number || "N/A";
                    document.getElementById('cookie').textContent = navigator.cookieEnabled ? "Enabled" : "Disabled";
                })
                .catch(error => {
                    alert("Failed to retrieve IP details. Please try again.");
                    console.error(error);
                });
        }

        function refreshPage() {
    // Clear the IP input field
    document.getElementById('ip-input').value = '';
    
    // Reset all the IP details fields to '-'
    document.getElementById('ipv4').textContent = '-';
    document.getElementById('ip-location').textContent = '-';
    document.getElementById('isp').textContent = '-';
    document.getElementById('proxy').textContent = '-';
    document.getElementById('platform').textContent = '-';
    document.getElementById('ipv6').textContent = '-';
    document.getElementById('country-code').textContent = '-';
    document.getElementById('ip-number').textContent = '-';
    document.getElementById('cookie').textContent = '-';
}

        document.querySelector('.fa-moon').addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
});

document.querySelector('.fa-expand').addEventListener('click', () => {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen();
    } else if (document.exitFullscreen) {
        document.exitFullscreen();
    }
});

document.querySelector('.search-bar input').addEventListener('input', function() {
    const query = this.value.toLowerCase(); // Get the current search term
    const infoItems = document.querySelectorAll('.info-item'); // Get all info items in the IP details section
    let found = false; // Flag to track if any match is found

    infoItems.forEach(item => {
        const label = item.querySelector('span').textContent.toLowerCase(); // Get the label text
        const value = item.querySelector('span:nth-child(2)').textContent.toLowerCase(); // Get the value text
        
        // Check if either the label or value contains the search term
        if (label.includes(query) || value.includes(query)) {
            item.style.display = 'flex'; // Show item if it matches
            found = true;
        } else {
            item.style.display = 'none'; // Hide item if it doesn't match
        }
    });

    // Optional: Show a message when no results are found
    if (!found && query !== "") {
        console.log('No results found');
    }
});