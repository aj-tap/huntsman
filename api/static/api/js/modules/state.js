export const state = {
    services: [],
    selectedServices: new Set(),
    activeTaskIds: [],
    tasks: {}, 
    pollingInterval: null,
    cy: null,
    stixObjects: new Map(),
    correlationMatches: {},
    pendingPivot: null,
    hiddenTypes: new Set(),
    pivotModal: null,
    patterns: {},
    superdb: null,
    explorerData: null
};