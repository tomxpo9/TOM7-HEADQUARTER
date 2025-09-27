// PTY interactive client
let ptyId = null;
let es = null;

const ptyOutput = document.getElementById('pty-output');
const ptyInput = document.getElementById('pty-input');
const btnSend = document.getElementById('pty-send');
const btnCtrlC = document.getElementById('pty-ctrlc');
const btnCtrlZ = document.getElementById('pty-ctrlz');
const btnClear = document.getElementById('pty-clear');
const btnStart = document.getElementById('pty-start');

function appendPty(text){
    if(!ptyOutput) return;
    ptyOutput.textContent += text;
    ptyOutput.scrollTop = ptyOutput.scrollHeight;
}

btnStart.addEventListener('click', () => {
    if(ptyId) return;
    fetch('/pty/start', {method: 'POST'}).then(r=>r.json()).then(data=>{
        if(data.id){
            ptyId = data.id;
            startPtyStream(ptyId);
            btnStart.disabled = true;
            btnCtrlC.disabled = false;
            btnCtrlZ.disabled = false;
        } else {
            appendPty('[failed to start pty]\n');
        }
    }).catch(()=> appendPty('[start error]\n'));
});

function startPtyStream(id){
    es = new EventSource('/pty/stream/' + id);
    es.onmessage = function(e){
        appendPty(e.data);
    };
    es.addEventListener('end', function(e){
        appendPty('\n[PTY CLOSED]\n');
        cleanupPty();
    });
    es.onerror = function(){
        // ignore transient errors; cleanup will happen on end
    };
}

btnSend.addEventListener('click', sendPtyInput);
ptyInput.addEventListener('keydown', function(e){
    if(e.key === 'Enter'){
        e.preventDefault();
        sendPtyInput();
    }
});

function sendPtyInput(){
    if(!ptyId){
        appendPty('[pty not started]\n');
        return;
    }
    const text = ptyInput.value || '';
    fetch('/pty/write/' + ptyId, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({input: text + '\n'})
    }).catch(()=>{ appendPty('[write failed]\n'); });
    ptyInput.value = '';
}

// Ctrl+C
btnCtrlC.addEventListener('click', () => {
    if(!ptyId){
        appendPty('[pty not started]\n');
        return;
    }
    if(!confirm('Send Ctrl+C to the interactive shell?')) return;
    fetch('/pty/sigint/' + ptyId, {method: 'POST'})
    .then(r=>r.json()).then(d=>{
        if(d.sent) appendPty('\n[Sent Ctrl+C]\n');
        else appendPty('\n[Ctrl+C failed]\n');
    }).catch(()=> appendPty('\n[Ctrl+C error]\n'));
});

// Ctrl+Z -> suspend then kill (force)
btnCtrlZ.addEventListener('click', () => {
    if(!ptyId){
        appendPty('[pty not started]\n');
        return;
    }
    if(!confirm('Send Ctrl+Z (force kill) to the interactive shell? This will terminate the shell process.')) return;
    fetch('/pty/ctrlz/' + ptyId, {method: 'POST'})
    .then(r=>r.json()).then(d=>{
        if(d.killed) appendPty('\n[Sent Ctrl+Z and killed process]\n');
        else appendPty('\n[Ctrl+Z failed]\n');
        cleanupPty();
    }).catch(()=>{ appendPty('\n[Ctrl+Z error]\n'); cleanupPty(); });
});

btnClear.addEventListener('click', ()=>{
    if(ptyOutput) ptyOutput.textContent = '';
});

function cleanupPty(){
    try { if(es) es.close(); } catch(e){}
    es = null;
    ptyId = null;
    btnStart.disabled = false;
    btnCtrlC.disabled = true;
    btnCtrlZ.disabled = true;
}
