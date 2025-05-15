export function initializeAIInsights(magicWandButtonId, aiInsightsContainerId, aiInsightsContentId, csrfToken) {
    const magicWandButton = document.getElementById(magicWandButtonId);
    const aiInsightsContainer = document.getElementById(aiInsightsContainerId);
    const aiInsightsContent = document.getElementById(aiInsightsContentId);
    const taskIds = localStorage.getItem('task_ids');

    if (!magicWandButton) {
        console.error("Magic Wand button not found.");
        return;
    }

    magicWandButton.addEventListener("click", () => {
        magicWandButton.disabled = true;
        magicWandButton.classList.add('disabled');
        aiInsightsContent.innerHTML = `
        <i class="fas fa-spinner fa-spin"></i> Orchestrator CTI is now processing the threat intel data gathered and performing additional research and reasoning.`;                
        aiInsightsContainer.style.display = "block";

        fetch('/api/tasks/create-ai/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ task_ids: taskIds })
        })
        .then(response => response.json())
        .then(data => {
            if (data.task_id) {
                console.log("AI Task Created:", data.task_id);
                pollTaskResult(data.task_id, aiInsightsContent, magicWandButton);
            } else {
                aiInsightsContent.innerText = "Error creating AI task. Please try again.";
            }
        })
        .catch(error => {
            aiInsightsContent.innerText = `Error: ${error}`;
        });
    });
}

function pollTaskResult(taskId, aiInsightsContent, magicWandButton) {
    const interval = setInterval(() => {
        fetch('/api/tasks/retrieve-ai/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ task_ids: taskId })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === "STARTED" || data.status === "PENDING") {
                console.log("AI task still processing...");
            } else if (data) {
                clearInterval(interval);
            
                let descriptions = "";
                if (Array.isArray(data)) {
                    // If data is an array, map descriptions
                    descriptions = data.map(item => item.description).join('\n'); // Join with newline for processing
                } else if (data.description) {
                    // If data is a single object with description
                    descriptions = data.description;
                }
                // --- Markdown-like formatting processing ---
                const processedLines = descriptions.split('\n').map(line => {
                    // Handle horizontal rule '---'
                    if (line.trim() === '---') {
                        return '<hr>';
                    }

                    let processedLine = line;

                    // Handle bold text (*text*) - simple implementation
                    // This regex finds text between single asterisks, ensuring they are not part of a word
                    processedLine = processedLine.replace(/\*(.+?)\*/g, '<strong>$1</strong>');


                    // Handle list items (* or •)
                    if (processedLine.trim().startsWith('* ')) {
                        // Remove the leading bullet and space, then wrap in <li>
                        processedLine = `<li>${processedLine.trim().substring(2)}</li>`;
                    } else if (processedLine.trim().startsWith('• ')) {
                         // Remove the leading bullet and space, then wrap in <li>
                         processedLine = `<li>${processedLine.trim().substring(2)}</li>`;
                    } else {
                        // For lines that are not list items or horizontal rules,
                        // we might want to add a line break if they are not empty.
                        // However, joining with <br> later handles this for non-list/non-hr lines.
                        // Keep the line as is for now.
                    }

                    return processedLine;
                });

                // Join lines back. Wrap in <ul> if any list items were found.
                // A simple check: if any processed line starts with <li>
                const hasListItems = processedLines.some(line => line.trim().startsWith('<li>'));
                // Join lines. If there are list items, join directly (<ul> will handle structure).
                // If no list items, join with <br> for simple line breaks.
                // Also handle <hr> which should be on its own line.
                const finalHtml = processedLines.map(line => {
                    if (line === '<hr>') {
                        return '<hr>';
                    } else if (line.trim().startsWith('<li>')) {
                         return line; // Keep list items as they are
                    } else {
                         // For non-list, non-hr lines, add <br> if not empty
                         return line.trim() === '' ? '' : `${line}<br>`;
                    }
                }).join(''); // Join everything without extra characters, <br> and <hr> handle spacing

                // Remove trailing <br> if present
                 if (finalHtml.endsWith('<br>')) {
                    aiInsightsContent.innerHTML = finalHtml.slice(0, -4);
                } else {
                    aiInsightsContent.innerHTML = finalHtml; // Set processed HTML content
                }

                document.dispatchEvent(new CustomEvent("AIInsightsReceived", { detail: data }));
            } else if (data.error) {
                clearInterval(interval);
                aiInsightsContent.innerText = `Error: ${data.error}`;
            }
        })
        .catch(error => {
            clearInterval(interval);
            aiInsightsContent.innerText = `Error: ${error}`;
        });
    }, 6000);  // Poll every 6 seconds
}

function getCsrfToken() {
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;
    return csrfToken;
}
