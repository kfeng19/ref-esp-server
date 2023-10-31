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
