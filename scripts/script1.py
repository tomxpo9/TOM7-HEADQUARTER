#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading, subprocess, shutil, sqlite3, os, base64, hashlib, requests, json
from Crypto.Cipher import AES
import jwt

BG_IMAGE = "TOM.jpg"
AI_NAME = "TOM7X GPT V12"
DB_FILE = "TOM7UltimateGPTV13.db"
BREACH_API_KEY = "b5ccaf4ecemsh68a8d93af91787cp139659jsn546b0cfdfdf7"

ALL_TOOLS = [
    "Nmap Scan","SQLMap","Hydra","Dirsearch","WPScan","Nikto","Masscan","Metasploit",
    "Whois Lookup","DNS Lookup","Subdomain Finder","Wayback URLs","BreachSearch Email","Phone Tracker","IP Tracker",
    "Base64 Encode","Base64 Decode","MD5 Hash","SHA1 Hash","SHA256 Hash","AES Encrypt","AES Decrypt","JWT Encode","JWT Decode"
]

TOOL_EXEC = {
    "Nmap Scan":"nmap","SQLMap":"sqlmap","Hydra":"hydra","Dirsearch":"dirsearch",
    "WPScan":"wpscan","Nikto":"nikto","Masscan":"masscan","Metasploit":"msfconsole",
    "Whois Lookup":"whois","DNS Lookup":"nslookup","Subdomain Finder":"amass",
    "Wayback URLs":"waybackurls"
}

TOOL_ARGS = {
    "Nmap Scan":["-sS","-sT","-O","-A","-Pn","-p 1-65535"],
    "SQLMap":["--level 1","--level 2","--risk 1","--dbs","--tables","--threads 5"],
    "Hydra":["-L user.txt","-P pass.txt","-s 22","-t 4","-f","-V"],
    "Dirsearch":["-u","-e php,html,js","-x 404,500","-t 50"],
    "WPScan":["--enumerate u","--enumerate p","--url","--plugins-detection mixed"],
    "Nikto":["-h","-Tuning x","-output nikto.txt"],
    "Masscan":["-p1-65535","--rate 1000"],
    "Metasploit":["-q","-x","-r resource.rc"],
    "Subdomain Finder":["-d example.com","-oA output"],
    "Wayback URLs":["-u","-o output.txt"]
}

class TOM7UltimateAppV13:
    def __init__(self, root):
        self.root=root
        self.root.title(AI_NAME)
        self.root.geometry("1600x900")
        self.mode=tk.StringVar(value="Safe")
        self.init_db()
        self.detected_tools=self.detect_tools()
        self.create_gui()

    def init_db(self):
        self.conn=sqlite3.connect(DB_FILE,check_same_thread=False)
        self.cursor=self.conn.cursor()
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool TEXT,
            target TEXT,
            mode TEXT,
            output TEXT
        )""")
        self.conn.commit()

    def detect_tools(self):
        available=[]
        for tool in ALL_TOOLS:
            if tool in TOOL_EXEC and shutil.which(TOOL_EXEC[tool]):
                available.append(tool)
            else:
                available.append(tool)  # include python tools
        return available

    def create_gui(self):
        header=tk.Frame(self.root,bg="#071827",height=40)
        header.pack(side="top",fill="x")
        tk.Label(header,text=AI_NAME,font=("Arial",18,"bold"),fg="#00f0ff",bg="#071827").pack(side="left",padx=10)
        tk.Label(header,text="Mode:",bg="#071827",fg='#dbeafe').pack(side="left",padx=5)
        ttk.Combobox(header,textvariable=self.mode,values=["Safe","Harm"],state="readonly",width=10).pack(side="left")
        tk.Button(header,text="Refresh Tools",bg="#00ffaa",fg="black",command=self.refresh_tools).pack(side="left",padx=5)
        tk.Button(header,text="Exit",command=self.root.quit,bg="#ff4444",fg="white").pack(side="right",padx=10)

        # Scrollable canvas
        self.tool_frame_outer=tk.Frame(self.root)
        self.tool_frame_outer.pack(fill="both",expand=True)
        self.tool_canvas=tk.Canvas(self.tool_frame_outer,bg="#071827")
        self.tool_scrollbar_y=tk.Scrollbar(self.tool_frame_outer,orient="vertical",command=self.tool_canvas.yview)
        self.tool_scrollbar_x=tk.Scrollbar(self.tool_frame_outer,orient="horizontal",command=self.tool_canvas.xview)
        self.tool_canvas.configure(yscrollcommand=self.tool_scrollbar_y.set,xscrollcommand=self.tool_scrollbar_x.set)
        self.tool_scrollbar_y.pack(side="right",fill="y")
        self.tool_scrollbar_x.pack(side="bottom",fill="x")
        self.tool_canvas.pack(side="left",fill="both",expand=True)
        self.tool_inner_frame=tk.Frame(self.tool_canvas,bg="#071827")
        self.tool_canvas.create_window((0,0),window=self.tool_inner_frame,anchor="nw")
        self.tool_inner_frame.bind("<Configure>", lambda e:self.tool_canvas.configure(scrollregion=self.tool_canvas.bbox("all")))

        self.add_tool_buttons_grid()

        self.target_entry=tk.Entry(self.root,width=50)
        self.target_entry.pack(pady=5)
        self.target_entry.insert(0,"Enter target here")

    def add_tool_buttons_grid(self):
        row=0
        col=0
        max_cols=8
        for tool in ALL_TOOLS:
            color="#00ff99" if tool in TOOL_ARGS else "#ffaa00"
            state="normal" if tool in self.detected_tools else "disabled"
            btn=tk.Button(self.tool_inner_frame,text=tool,bg=color,
                          command=lambda t=tool:self.open_tool_args_window(t),state=state,width=12,height=1)
            btn.grid(row=row,column=col,padx=3,pady=3)
            col+=1
            if col>=max_cols:
                col=0
                row+=1

    def refresh_tools(self):
        self.detected_tools=self.detect_tools()
        for w in self.tool_inner_frame.winfo_children():
            if isinstance(w,tk.Button): w.destroy()
        self.add_tool_buttons_grid()
        self.root.after(0, lambda: messagebox.showinfo("Refresh","Tools refreshed!"))

    def open_tool_args_window(self,tool_name):
        win=tk.Toplevel(self.root)
        win.title(f"{tool_name} Options")
        tk.Label(win,text=f"Target / Input for {tool_name}").pack()
        target_entry=tk.Entry(win,width=40)
        target_entry.pack(pady=5)
        target_entry.insert(0,self.target_entry.get().strip())
        args_list=TOOL_ARGS.get(tool_name,[])
        checkboxes={}
        if args_list:
            tk.Label(win,text="Select Arguments:").pack(anchor="w")
            for arg in args_list:
                var=tk.BooleanVar()
                cb=tk.Checkbutton(win,text=arg,variable=var)
                cb.pack(anchor="w")
                checkboxes[arg]=var

        tk.Button(win,text="Run",bg="#00f0ff",
                  command=lambda:self.run_tool_thread(tool_name,target_entry,checkboxes)).pack(pady=5)

    def run_tool_thread(self,tool_name,target_entry,checkboxes):
        threading.Thread(target=self.run_tool,args=(tool_name,target_entry,checkboxes)).start()

    def run_tool(self,tool_name,target_entry,checkboxes):
        target=target_entry.get().strip()
        output=""
        try:
            if tool_name=="Base64 Encode": output=base64.b64encode(target.encode()).decode()
            elif tool_name=="Base64 Decode": output=base64.b64decode(target.encode()).decode()
            elif tool_name=="MD5 Hash": output=hashlib.md5(target.encode()).hexdigest()
            elif tool_name=="SHA1 Hash": output=hashlib.sha1(target.encode()).hexdigest()
            elif tool_name=="SHA256 Hash": output=hashlib.sha256(target.encode()).hexdigest()
            elif tool_name=="AES Encrypt":
                key=b"16byteslongkey!!"
                cipher=AES.new(key,AES.MODE_EAX)
                ciphertext,tag=cipher.encrypt_and_digest(target.encode())
                output=f"Cipher: {ciphertext.hex()}\nNonce: {cipher.nonce.hex()}\nTag: {tag.hex()}"
            elif tool_name=="AES Decrypt":
                messagebox.showinfo("Info","AES Decrypt requires manual input of cipher, nonce, tag (demo mode)")
            elif tool_name=="JWT Encode":
                payload={"data":target}
                output=jwt.encode(payload,"secret",algorithm="HS256")
            elif tool_name=="JWT Decode":
                try:
                    decoded=jwt.decode(target,"secret",algorithms=["HS256"])
                    output=json.dumps(decoded,indent=2)
                except Exception as e: output=f"Error: {e}"
            elif tool_name=="IP Tracker":
                r=requests.get(f"https://ipinfo.io/{target}/json").json()
                loc=r.get("loc","")
                output=f"{target} => {r.get('city','')}, {r.get('region','')}, {r.get('country','')}\nGoogle Maps: https://www.google.com/maps?q={loc}"
            elif tool_name=="BreachSearch Email":
                try:
                    headers={"Authorization":f"Bearer {BREACH_API_KEY}"}
                    r=requests.get(f"https://api.breach.sh/v1/{target}",headers=headers).json()
                    output=json.dumps(r,indent=2)
                except Exception as e: output=f"Error: {e}"
            else:
                binary=TOOL_EXEC.get(tool_name)
                if not binary or shutil.which(binary) is None:
                    self.root.after(0, lambda: messagebox.showerror("Error",f"{tool_name} executable not found!"))
                    return
                selected_args=[a for a,v in checkboxes.items() if v.get()] if checkboxes else []
                cmd=[binary]+selected_args+([target] if target else [])
                result=subprocess.run(cmd,capture_output=True,text=True)
                output=result.stdout+("\nERROR:"+result.stderr if result.stderr else "")
        except Exception as e:
            output=f"Exception: {e}"

        self.root.after(0, lambda:self.show_output_window(tool_name,output))

        self.cursor.execute("INSERT INTO logs(tool,target,mode,output) VALUES (?,?,?,?)",
                            (tool_name,target,self.mode.get(),output[:1000]))
        self.conn.commit()

    def show_output_window(self,tool_name,output):
        out_win=tk.Toplevel(self.root)
        out_win.title(f"{tool_name} Output")
        txt=ScrolledText(out_win,bg="black",fg="#00ffcc")
        txt.pack(fill="both",expand=True)
        txt.insert("end",output)
        txt.configure(state="disabled")


if __name__=="__main__":
    root=tk.Tk()
    app=TOM7UltimateAppV13(root)
    root.mainloop()
