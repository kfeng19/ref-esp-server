function postRequest1() {
    fetch('/api/led', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ state: true })
    });
}

function postRequest2() {
    fetch('/api/led', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ state: false })
    });
}

function measure_request1() {
    fetch('/api/measure/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    });
}

function measure_request2() {
    fetch('/api/measure/stop', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    });
}
