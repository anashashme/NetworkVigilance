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

// Live search functionality
document.querySelector('.search-bar input').addEventListener('input', function() {
    const query = this.value.toLowerCase(); // Get the current search term
    const faqItems = document.querySelectorAll('.faq-item'); // Get all FAQ items
    let found = false; // Flag to track if any match is found

    faqItems.forEach(item => {
        const title = item.querySelector('h3').textContent.toLowerCase(); // Get the FAQ title text
        const description = item.querySelector('p').textContent.toLowerCase(); // Get the FAQ description text
        
        // Check if either the title or description contains the search term
        if (title.includes(query) || description.includes(query)) {
            item.style.display = 'flex'; // Show item if it matches
            found = true;
        } else {
            item.style.display = 'none'; // Hide item if it doesn't match
        }
    });

    // If no matches are found, you can optionally show a message
    if (!found && query !== "") {
        // Optional: Show a message when no results are found
        console.log('No results found');
    }
});