function runScript(scriptName){
    fetch('/run/' + scriptName)
    .then(r => r.json())
    .then(data => {
        const statusId = 'status-' + scriptName.replace(/\./g, '-');
        const el = document.getElementById(statusId);
        if(el) {
            el.textContent = data.status;
            el.classList.toggle('not-available', data.status === 'Services Not Available!');
        }
    });
}

function stopToolConfirm(scriptName){
    if(!confirm('Are you sure you want to stop this tool?')) return;
    fetch('/stop_tool/' + scriptName, {method: 'POST'})
    .then(r => r.json())
    .then(data => {
        const statusId = 'status-' + scriptName.replace(/\./g, '-');
        const el = document.getElementById(statusId);
        if(el) {
            el.textContent = data.status || 'Services Online';
            el.classList.toggle('not-available', (data.status === 'Services Not Available!'));
        }
    });
}

setInterval(()=>{
    document.querySelectorAll('.TOOLS-OPTIONS').forEach(card=>{
        const scriptName = card.getAttribute('data-script');
        fetch('/status/' + scriptName)
        .then(r=>r.json())
        .then(d=>{
            const id = 'status-' + scriptName.replace(/\./g, '-');
            const el = document.getElementById(id);
            if(el){
                el.textContent = d.status;
                el.classList.toggle('not-available', d.status === 'Services Not Available!');
            }
        }).catch(()=>{});
    });
}, 1000);
