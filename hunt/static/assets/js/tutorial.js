export function initializeTutorial(tutorialModeToggleId, tutorialModalId, nextStepBtnId, prevStepBtnId, skipTutorialBtnId, tutorialDiagramId, tutorialInstructionsId) {
    const tutorialModeToggle = document.getElementById(tutorialModeToggleId);
    const tutorialModal = new bootstrap.Modal(document.getElementById(tutorialModalId));
    const nextStepBtn = document.getElementById(nextStepBtnId);
    const prevStepBtn = document.getElementById(prevStepBtnId);
    const skipTutorialBtn = document.getElementById(skipTutorialBtnId);
    const tutorialDiagram = document.getElementById(tutorialDiagramId);
    const tutorialInstructions = document.getElementById(tutorialInstructionsId);

    let currentStep = 0;
    const tutorialSteps = [
        {
            target: '#stixResults',
            diagram: '<p>Diagram for Graph View</p>', // Replace with actual diagram content
            instructions: 'This is the Graph View. It shows the relationships between different indicators of compromise (IOCs).'
        },
        {
            target: '#query',
            diagram: '<p>Diagram for Query Input</p>', // Replace with actual diagram content
            instructions: 'This is the Query Input. You can enter SuperDB/SQL-like queries here to search for specific data.'
        },
        {
            target: '#magicWandButton',
            diagram: '<p>Diagram for Insights Button</p>', // Replace with actual diagram content
            instructions: 'Click the "Insights" button to get AI-powered analysis of the data.'
        },
        {
            target: '#queryHistoryDropdown',
            diagram: '<p>Diagram for History Dropdown</p>', // Replace with actual diagram content
            instructions: 'The "History" dropdown allows you to quickly access and reuse your previous queries.'
        },
        {
            target: '#queryExamplesDropdown',
            diagram: '<p>Diagram for Examples Dropdown</p>', // Replace with actual diagram content
            instructions: 'The "Examples" dropdown provides pre-built queries to help you get started.'
        },
        {
            target: '#resultTableContainer',
            diagram: '<p>Diagram for Results Table</p>', // Replace with actual diagram content
            instructions: 'The results of your query will be displayed in this table.'
        }
    ];

    function showTutorialStep(stepIndex) {
        if (stepIndex < 0 || stepIndex >= tutorialSteps.length) return;

        // Remove previous highlight
        document.querySelectorAll('.highlight').forEach(el => el.classList.remove('highlight'));

        currentStep = stepIndex;
        const step = tutorialSteps[currentStep];
        const targetElement = document.querySelector(step.target);

        if (targetElement) {
            targetElement.classList.add('highlight');
            // Scroll to the target element
            targetElement.scrollIntoView({
                behavior: 'smooth',
                block: 'center'
            });
            tutorialDiagram.innerHTML = step.diagram;
            tutorialInstructions.innerHTML = step.instructions;
            tutorialModal.show();
        }

        // Update button states
        prevStepBtn.disabled = currentStep === 0;
        nextStepBtn.disabled = currentStep === tutorialSteps.length - 1;
    }

    // Tutorial Mode Toggle Logic
    tutorialModeToggle.addEventListener('change', function() {
        if (this.checked) {
            showTutorialStep(0);
        } else {
            // Remove highlight and close modal
            document.querySelectorAll('.highlight').forEach(el => el.classList.remove('highlight'));
            tutorialModal.hide();
        }
    });

    // Navigation buttons
    nextStepBtn.addEventListener('click', () => showTutorialStep(currentStep + 1));
    prevStepBtn.addEventListener('click', () => showTutorialStep(currentStep - 1));
    skipTutorialBtn.addEventListener('click', () => {
        tutorialModeToggle.checked = false;
        // Remove highlight and close modal
        document.querySelectorAll('.highlight').forEach(el => el.classList.remove('highlight'));
        tutorialModal.hide();
    });
    // Close modal when click outside
    tutorialModal._element.addEventListener('hidden.bs.modal', function () {
        // Remove highlight
        document.querySelectorAll('.highlight').forEach(el => el.classList.remove('highlight'));
        tutorialModal.hide();
    });
}
