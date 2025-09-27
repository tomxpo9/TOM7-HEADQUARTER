from flask import Flask, render_template, jsonify, request, Response
import os, subprocess, shutil, shlex, uuid, pty, select, time, signal

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

scripts_folder = 'scripts'
scripts_list = [f'script{i}.py' for i in range(1, 11)]
display_names = ["TOM7X-GPT","TOM7-ARMED DDOS","TOM7SQL","TOM7-ALGORITHM DESTROYER","Digital Art",
                 "TOM7NET-RAPTOR","TOM7X-EYES","TOM7X-DEF","TOM7-XARCH","TOM7X-DIR-INSPECTOR"]
script_alias = dict(zip(scripts_list, display_names))

script_processes = {}   # terminal-launched tools
pty_sessions = {}       # exec_id -> { pid, master_fd, alive }

def get_terminal_command(script_path):
    if shutil.which("gnome-terminal"):
        return ["gnome-terminal", "--", "bash", "-c", f"python3 {shlex.quote(script_path)}; exec bash"]
    if shutil.which("xterm"):
        return ["xterm", "-hold", "-e", f"python3 {shlex.quote(script_path)}"]
    if shutil.which("konsole"):
        return ["konsole", "-e", f"python3 {shlex.quote(script_path)}"]
    return ["setsid", "python3", script_path]

def run_script_in_terminal(script_name):
    script_path = os.path.join(scripts_folder, script_name)
    if not os.path.exists(script_path) or os.path.getsize(script_path) == 0:
        return "Services Not Available!"
    proc = script_processes.get(script_name)
    if proc and proc.poll() is None:
        return "LAUNCHED >>>"
    cmd = get_terminal_command(script_path)
    proc = subprocess.Popen(cmd)
    script_processes[script_name] = proc
    return "LAUNCHED >>>"

def stop_script(script_name):
    proc = script_processes.get(script_name)
    if not proc:
        return False
    if proc.poll() is None:
        try:
            proc.terminate()
            return True
        except:
            try:
                proc.kill()
                return True
            except:
                return False
    return True

def get_status(script_name):
    path = os.path.join(scripts_folder, script_name)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return "Services Not Available!"
    proc = script_processes.get(script_name)
    if proc and proc.poll() is None:
        return "LAUNCHED >>>"
    return "Services Online"

@app.route('/')
def index():
    status_dict = {s: get_status(s) for s in scripts_list}
    return render_template('TOM7V2.html', scripts=status_dict, aliases=script_alias)

@app.route('/run/<script_name>')
def run_tool(script_name):
    if script_name not in scripts_list:
        return jsonify({"status": "Not Found"}), 404
    status = run_script_in_terminal(script_name)
    return jsonify({"status": status})

@app.route('/stop_tool/<script_name>', methods=['POST'])
def stop_tool(script_name):
    if script_name not in scripts_list:
        return jsonify({"status": "Not Found"}), 404
    ok = stop_script(script_name)
    return jsonify({"stopped": ok, "status": get_status(script_name)})

@app.route('/status/<script_name>')
def status(script_name):
    if script_name not in scripts_list:
        return jsonify({"status": "Not Found"}), 404
    return jsonify({"status": get_status(script_name)})

# ----------------- PTY interactive shell endpoints -----------------

def spawn_pty_shell():
    master_fd, slave_fd = pty.openpty()
    pid = os.fork()
    if pid == 0:
        # child: attach slave as controlling terminal and exec bash
        os.setsid()
        os.close(master_fd)
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        try:
            os.execv("/bin/bash", ["/bin/bash", "--noprofile", "--norc"])
        except Exception:
            os._exit(1)
    else:
        # parent
        os.close(slave_fd)
        return pid, master_fd

@app.route('/pty/start', methods=['POST'])
def pty_start():
    exec_id = str(uuid.uuid4())
    try:
        pid, master_fd = spawn_pty_shell()
    except Exception as e:
        return jsonify({"error": f"failed to spawn pty: {str(e)}"}), 500
    pty_sessions[exec_id] = {"pid": pid, "master_fd": master_fd, "alive": True}
    return jsonify({"id": exec_id}), 200

@app.route('/pty/stream/<exec_id>')
def pty_stream(exec_id):
    session = pty_sessions.get(exec_id)
    if not session:
        return jsonify({"error": "not found"}), 404
    master_fd = session["master_fd"]
    def generator():
        try:
            while True:
                pid = session.get("pid")
                if pid:
                    try:
                        pid_out, status = os.waitpid(pid, os.WNOHANG)
                        if pid_out == pid:
                            break
                    except ChildProcessError:
                        break
                r, _, _ = select.select([master_fd], [], [], 0.2)
                if master_fd in r:
                    try:
                        chunk = os.read(master_fd, 1024)
                    except OSError:
                        break
                    if not chunk:
                        break
                    try:
                        text = chunk.decode(errors='replace')
                    except:
                        text = str(chunk)
                    # send raw lines (preserve newlines)
                    for line in text.splitlines(True):
                        # SSE newline escaping handled: send one data: line per line
                        yield f"data: {line.rstrip('\\n')}\n\n"
                time.sleep(0.01)
        except GeneratorExit:
            pass
        except Exception as e:
            yield f"data: [pty error] {str(e)}\n\n"
        finally:
            yield "event: end\ndata: [PTY CLOSED]\n\n"
    return Response(generator(), mimetype='text/event-stream', headers={"Cache-Control": "no-cache"})

@app.route('/pty/write/<exec_id>', methods=['POST'])
def pty_write(exec_id):
    session = pty_sessions.get(exec_id)
    if not session:
        return jsonify({"error": "not found"}), 404
    master_fd = session["master_fd"]
    data = request.json or {}
    text = data.get('input', '')
    if text is None:
        text = ''
    try:
        os.write(master_fd, text.encode())
    except OSError as e:
        return jsonify({"error": f"write error: {str(e)}"}), 500
    return jsonify({"written": True})

@app.route('/pty/sigint/<exec_id>', methods=['POST'])
def pty_sigint(exec_id):
    """Send SIGINT (Ctrl+C) to the PTY child process."""
    session = pty_sessions.get(exec_id)
    if not session:
        return jsonify({"error": "not found"}), 404
    pid = session.get("pid")
    try:
        if pid:
            os.kill(pid, signal.SIGINT)
            return jsonify({"sent": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"sent": False}), 500

@app.route('/pty/ctrlz/<exec_id>', methods=['POST'])
def pty_ctrlz(exec_id):
    """Simulate Ctrl+Z then ensure kill (suspend then kill to forcibly stop)."""
    session = pty_sessions.get(exec_id)
    if not session:
        return jsonify({"error": "not found"}), 404
    pid = session.get("pid")
    try:
        if pid:
            os.kill(pid, signal.SIGTSTP)
            time.sleep(0.05)
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
            try:
                os.waitpid(pid, 0)
            except Exception:
                pass
            master_fd = session.get("master_fd")
            if master_fd:
                try:
                    os.close(master_fd)
                except:
                    pass
            session["alive"] = False
            pty_sessions.pop(exec_id, None)
            return jsonify({"killed": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"killed": False}), 500

@app.route('/pty/stop/<exec_id>', methods=['POST'])
def pty_stop(exec_id):
    session = pty_sessions.get(exec_id)
    if not session:
        return jsonify({"stopped": False, "error": "not found"}), 404
    pid = session.get("pid")
    master_fd = session.get("master_fd")
    try:
        if pid:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.05)
            try:
                os.waitpid(pid, 0)
            except:
                pass
    except Exception:
        pass
    try:
        if master_fd:
            try:
                os.close(master_fd)
            except:
                pass
    except Exception:
        pass
    session["alive"] = False
    pty_sessions.pop(exec_id, None)
    return jsonify({"stopped": True})

if __name__ == "__main__":
    # bind to localhost by default for safety
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
