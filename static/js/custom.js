
function copyToClipboard(text, iconElement) {
    navigator.clipboard.writeText(text).then(function() {
        
        // Change icon temporarily to checkmark
        iconElement.classList.remove("bi-clipboard");
        iconElement.classList.add("bi-check-lg");
        iconElement.classList.remove("text-primary");
        iconElement.classList.add("text-success");

        // Revert back after 1.5 seconds
        setTimeout(function() {
            iconElement.classList.remove("bi-check-lg");
            iconElement.classList.add("bi-clipboard");
            iconElement.classList.remove("text-success");
            iconElement.classList.add("text-primary");
        }, 1500);

    }).catch(function(err) {
        console.error("Failed to copy: ", err);
    });
}

