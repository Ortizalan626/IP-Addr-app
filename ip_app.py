import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re
from datetime import datetime
import tempfile
import os
import threading

# ----------------------------- NET / VALIDATION -----------------------------
IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
CREATE_NO_WINDOW = 0x08000000
BATCH_SIZE = 25

CHECK_OFF = "☐"
CHECK_ON = "☑"


def is_valid_ip(ip: str) -> bool:
    ip = ip.strip()
    if not IP_PATTERN.match(ip):
        return False
    try:
        return all(0 <= int(x) <= 255 for x in ip.split("."))
    except Exception:
        return False


def run_hidden(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=CREATE_NO_WINDOW
    )


def popen_hidden(cmd):
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=CREATE_NO_WINDOW
    )


def is_admin():
    try:
        r = run_hidden(["netsh", "interface", "ipv4", "show", "interfaces"])
        return r.returncode == 0
    except Exception:
        return False


def get_nics():
    try:
        r = run_hidden(["netsh", "interface", "show", "interface"])
        nics = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] in ("Enabled", "Disabled"):
                nics.append(" ".join(parts[3:]))
        return nics
    except Exception:
        return ["Ethernet"]


# PowerShell getter (good for Refresh)
def get_assigned_ips(nic):
    try:
        safe_nic = nic.replace("'", "''")
        ps_cmd = (
            f"try {{ "
            f"Get-NetIPAddress -InterfaceAlias '{safe_nic}' -AddressFamily IPv4 "
            f"| Select-Object -ExpandProperty IPAddress "
            f"}} catch {{ }}"
        )

        r = run_hidden([
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_cmd
        ])

        if r.returncode != 0:
            return []

        ips = []
        for line in (r.stdout or "").splitlines():
            ip = line.strip()
            if not ip:
                continue
            if is_valid_ip(ip) and not ip.startswith("169.254.") and ip != "0.0.0.0":
                ips.append(ip)

        return ips

    except Exception:
        return []


# ----------------------------- REMOVE/VERIFY HELPERS -----------------------------
def _get_assigned_ips_netsh_parse(nic):
    """Fast/robust verification source for deletes/adds (matches your working code idea)."""
    try:
        r = run_hidden(["netsh", "interface", "ipv4", "show", "addresses", f'name="{nic}"'])
        if r.returncode != 0:
            r = run_hidden(["netsh", "interface", "ipv4", "show", "addresses", f"name={nic}"])
        if r.returncode != 0:
            return []

        ips = []
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line.lower().startswith("ip address"):
                raw = line.split(":")[-1].strip()
                raw = raw.split("(")[0].strip()
                if is_valid_ip(raw) and not raw.startswith("169.254.") and raw != "0.0.0.0":
                    ips.append(raw)
        return ips
    except Exception:
        return []


def get_assigned_ips_verify(nic):
    """
    Use netsh parse for post-delete verification (more consistent with netsh operations).
    Fall back to PowerShell getter if netsh returns nothing.
    """
    ips = _get_assigned_ips_netsh_parse(nic)
    if ips:
        return ips
    return get_assigned_ips(nic)


# ----------------------------- TEXT WIDGET -----------------------------
class SafeScrolledText(ttk.Frame):
    def __init__(self, master, width=40, height=10):
        super().__init__(master)

        self.text = tk.Text(self, width=width, height=height, wrap="none")
        self.scroll = ttk.Scrollbar(self, command=self.text.yview)

        self.text.configure(yscrollcommand=self.scroll.set)

        self.text.pack(side="left", fill="both", expand=True)
        self.scroll.pack(side="right", fill="y")

        self._readonly = False

    def get_lines(self):
        raw = self.text.get("1.0", "end").strip()
        out = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            # allow lines like "☐ 10.0.0.1" / "☑ 10.0.0.1"
            if ln.startswith(CHECK_OFF) or ln.startswith(CHECK_ON):
                ln = ln[1:].strip()
            out.append(ln)
        return out

    def set_text(self, lines):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        if lines:
            self.text.insert("end", "\n".join(lines) + "\n")
        self.text.configure(state="disabled" if self._readonly else "normal")

    def append_line(self, line):
        self.text.configure(state="normal")
        self.text.insert("end", line + "\n")
        self.text.see("end")
        self.text.configure(state="disabled" if self._readonly else "normal")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")

    def set_readonly(self, ro):
        self._readonly = ro
        self.text.configure(state="disabled" if ro else "normal")


# ----------------------------- MAIN APP -----------------------------
class IPUtilityApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IP Utility")
        self.root.geometry("1000x760")

        # Native Windows theme
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:
            style.theme_use("default")

        self.root.option_add("*Font", ("Segoe UI", 9))

        # Track check state for "Remove Selected"
        self.assigned_checks = {}  # ip -> bool

        # Startup warning only
        if not is_admin():
            messagebox.showwarning(
                "Administrator Recommended",
                "Some actions require Administrator.\n"
                "If you see errors like 'requires elevation', run as Administrator."
            )

        # ---------------- TOP BAR ----------------
        self.top = ttk.Frame(self.root)
        self.top.pack(fill="x", padx=15, pady=10)

        ttk.Label(self.top, text="Network Adapter:").pack(side="left")
        self.nic_var = tk.StringVar()
        self.nic_combo = ttk.Combobox(self.top, textvariable=self.nic_var, width=35, state="readonly")
        self.nic_combo.pack(side="left", padx=(5, 20))

        ttk.Label(self.top, text="Subnet Mask:").pack(side="left")
        self.mask_entry = ttk.Entry(self.top, width=20)
        self.mask_entry.insert(0, "255.255.254.0")
        self.mask_entry.pack(side="left", padx=(5, 20))

        # ---------------- MAIN COLUMNS ----------------
        self.columns = ttk.Frame(self.root)
        self.columns.pack(fill="both", expand=True, padx=15)

        self.left = ttk.Frame(self.columns)
        self.left.pack(side="left", expand=True, fill="both", padx=(0, 10))

        self.right = ttk.Frame(self.columns)
        self.right.pack(side="left", expand=True, fill="both")

        ttk.Label(self.left, text="Paste IPs Here").pack(anchor="w")
        self.input_box = SafeScrolledText(self.left, width=50, height=20)
        self.input_box.pack(fill="both", expand=True)

        ttk.Label(self.right, text="IPs Currently Assigned to Adapter").pack(anchor="w")
        self.assigned_box = SafeScrolledText(self.right, width=50, height=20)
        self.assigned_box.pack(fill="both", expand=True)
        self.assigned_box.set_readonly(True)

        # Click-to-toggle checkboxes in assigned list
        self.assigned_box.text.bind("<Button-1>", self._on_assigned_click)

        # ---------------- BUTTON ROWS ----------------
        self.left_btns = ttk.Frame(self.left)
        self.left_btns.pack(fill="x", pady=8)

        self.add_btn = ttk.Button(self.left_btns, text="Add IPs to Adapter", command=self.add_ips)
        self.add_btn.pack(side="left", expand=True, fill="x")

        self.clear_btn = ttk.Button(self.left_btns, text="Clear List", command=self.input_box.clear)
        self.clear_btn.pack(side="left", padx=(5, 0))

        self.right_btns = ttk.Frame(self.right)
        self.right_btns.pack(fill="x", pady=8)

        self.remove_btn = ttk.Button(self.right_btns, text="Remove ALL Assigned IPs", command=self.remove_all)
        self.remove_btn.pack(side="left", expand=True, fill="x")

        self.remove_selected_btn = ttk.Button(self.right_btns, text="Remove Selected", command=self.remove_selected)
        self.remove_selected_btn.pack(side="left", padx=(5, 0))

        self.refresh_btn = ttk.Button(self.right_btns, text="Refresh Assigned List", command=self.refresh_assigned)
        self.refresh_btn.pack(side="left", padx=(5, 0))

        # ---------------- LOG AREA ----------------
        ttk.Label(self.root, text="Log:").pack(anchor="w", padx=15)

        self.log_box = SafeScrolledText(self.root, width=120, height=10)
        self.log_box.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        self.log_box.set_readonly(True)

        self.clear_log_btn = ttk.Button(self.root, text="Clear Log", command=self.clear_log)
        self.clear_log_btn.pack(anchor="e", padx=15, pady=(0, 10))

        # Load NICs
        self.nic_combo["values"] = get_nics()
        if self.nic_combo["values"]:
            self.nic_combo.current(0)

        self.refresh_assigned()

    # ---------------- Small helpers ----------------
    def _set_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.add_btn.configure(state=state)
        self.clear_btn.configure(state=state)
        self.remove_btn.configure(state=state)
        self.remove_selected_btn.configure(state=state)
        self.refresh_btn.configure(state=state)
        self.clear_log_btn.configure(state=state)
        self.nic_combo.configure(state="disabled" if busy else "readonly")
        self.mask_entry.configure(state="disabled" if busy else "normal")

    def _run_in_thread(self, work_fn, done_fn=None):
        def worker():
            try:
                result = work_fn()
                if done_fn:
                    self.root.after(0, lambda: done_fn(result, None))
            except Exception as e:
                if done_fn:
                    self.root.after(0, lambda: done_fn(None, e))

        threading.Thread(target=worker, daemon=True).start()

    # ---------------- LOGGING ----------------
    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.append_line(f"[{ts}] {msg}")

    def clear_log(self):
        self.log_box.clear()

    # ---------------- ASSIGNED LIST (CHECKBOX RENDER) ----------------
    def _render_assigned_with_checks(self, ips):
        old = dict(self.assigned_checks)
        self.assigned_checks = {ip: bool(old.get(ip, False)) for ip in ips}

        lines = []
        for ip in ips:
            lines.append(f"{CHECK_ON if self.assigned_checks.get(ip) else CHECK_OFF} {ip}")
        self.assigned_box.set_text(lines)

    def _on_assigned_click(self, event):
        t = self.assigned_box.text
        try:
            idx = t.index(f"@{event.x},{event.y}")
            line_s, col_s = idx.split(".")
            line = int(line_s)
            col = int(col_s)
        except Exception:
            return

        if col > 2:
            return

        line_text = t.get(f"{line}.0", f"{line}.end").strip()
        if not line_text:
            return

        parts = line_text.split(maxsplit=1)
        if len(parts) != 2:
            return

        ip = parts[1].strip()
        if not is_valid_ip(ip):
            return

        new_state = not bool(self.assigned_checks.get(ip, False))
        self.assigned_checks[ip] = new_state

        t.configure(state="normal")
        try:
            t.delete(f"{line}.0", f"{line}.1")
            t.insert(f"{line}.0", CHECK_ON if new_state else CHECK_OFF)
        finally:
            t.configure(state="disabled")

        return "break"

    def _get_selected_assigned_ips(self):
        return [ip for ip, checked in self.assigned_checks.items() if checked]

    # ---------------- REFRESH (NON-BLOCKING) ----------------
    def refresh_assigned(self):
        nic = self.nic_var.get()

        self._set_busy(True)
        self.log("Refreshing assigned IP list...")

        def work():
            return get_assigned_ips(nic)

        def done(ips, err):
            try:
                if err:
                    self.log(f"ERROR: {err}")
                    return
                self._render_assigned_with_checks(ips)
                self.log(f"Found {len(ips)} IPv4 address(es). ")
            finally:
                self._set_busy(False)

        self._run_in_thread(work, done)

    # ---------------- ADD IPs (NON-BLOCKING + NO DUPES + VERIFY + ERROR DETAILS) ----------------
    def add_ips(self):
        nic = self.nic_var.get()
        mask = self.mask_entry.get().strip()

        raw_lines = self.input_box.get_lines()
        valid = [ip for ip in raw_lines if is_valid_ip(ip)]

        if not valid:
            messagebox.showerror("Error", "No valid IPs.")
            return

        # De-dupe the pasted list while preserving order
        seen = set()
        ips_unique = []
        dup_in_input = 0
        for ip in valid:
            if ip in seen:
                dup_in_input += 1
                continue
            seen.add(ip)
            ips_unique.append(ip)

        self._set_busy(True)
        self.log(f"Adding {len(ips_unique)} IP(s)...")

        def work():
            existing = set(get_assigned_ips_verify(nic))
            pending = [ip for ip in ips_unique if ip not in existing]
            already = [ip for ip in ips_unique if ip in existing]

            added = []
            failed = []

            for i in range(0, len(pending), BATCH_SIZE):
                batch = pending[i:i + BATCH_SIZE]

                # run netsh batch
                script_lines = [
                    f'interface ipv4 add address name="{nic}" address={ip} mask={mask} store=persistent'
                    for ip in batch
                ]
                script_path = self._write_netsh_script(script_lines)

                try:
                    proc = popen_hidden(["netsh", "-f", script_path])
                    out, err = proc.communicate()
                    rc = proc.returncode
                finally:
                    try:
                        os.remove(script_path)
                    except Exception:
                        pass

                # VERIFY after batch
                current = set(get_assigned_ips_verify(nic))

                for ip in batch:
                    if ip in current:
                        added.append(ip)
                    else:
                        details = (err or out or "").strip()
                        if not details:
                            details = f"(netsh rc={rc}, but IP not observed after verification)"
                        failed.append((ip, details))

            return (added, failed, already, dup_in_input)

        def done(result, err):
            try:
                if err:
                    self.log(f"ERROR: {err}")
                    messagebox.showerror("Error", str(err))
                    return

                added, failed, already, dup_in_input_local = result

                if dup_in_input_local:
                    self.log(f"Skipped {dup_in_input_local} duplicate IP(s) in the pasted list.")

                for ip in already:
                    self.log(f"SKIP (already on NIC): {ip}")

                for ip in added:
                    self.log(f"Added: {ip}")

                # This is the part you asked for: netsh elevation errors show here
                if failed:
                    self.log(f"Removed 0 IP(s).")  # keep your same style/feel if you like
                    self.log(f"FAILED to add {len(failed)} IP(s). Showing first 10:")
                    for ip, details in failed[:10]:
                        self.log(f"  {ip} -> {details}")
                    if len(failed) > 10:
                        self.log(f"...and {len(failed) - 10} more failures.")
                    # Optional: popup (comment out if you only want log)
                    messagebox.showwarning(
                        "Some IPs not added",
                        f"Added {len(added)} IP(s), but {len(failed)} failed.\nCheck Log for details."
                    )

                if not added and not failed and (already or dup_in_input_local):
                    self.log("No new IPs needed to be added.")

                self.refresh_assigned()
                self.input_box.clear()
            finally:
                self._set_busy(False)

        self._run_in_thread(work, done)

    # ---------------- REMOVE ALL (NETSH + VERIFY) ----------------
    def remove_all(self):
        nic = self.nic_var.get()

        self._set_busy(True)
        self.log("Removing all assigned IPs...")

        def work():
            ips = get_assigned_ips_verify(nic)
            if not ips:
                return ([], [])

            removed = []
            failed = []

            for i in range(0, len(ips), BATCH_SIZE):
                batch = ips[i:i + BATCH_SIZE]

                script_lines = [
                    f'interface ipv4 delete address name="{nic}" address={ip}'
                    for ip in batch
                ]
                script_path = self._write_netsh_script(script_lines)

                try:
                    proc = popen_hidden(["netsh", "-f", script_path])
                    out, err = proc.communicate()
                    rc = proc.returncode
                finally:
                    try:
                        os.remove(script_path)
                    except Exception:
                        pass

                current = set(get_assigned_ips_verify(nic))

                for ip in batch:
                    if ip not in current:
                        removed.append(ip)
                    else:
                        details = (err or out or "").strip()
                        if not details:
                            details = f"(netsh rc={rc}, but IP still present after verification)"
                        failed.append((ip, details))

            return (removed, failed)

        def done(result, err):
            try:
                if err:
                    self.log(f"ERROR: {err}")
                    messagebox.showerror("Error", str(err))
                    return

                removed, failed = result

                for ip in removed:
                    self.assigned_checks.pop(ip, None)

                self.log(f"Removed {len(removed)} IP(s).")
                if failed:
                    self.log(f"FAILED to remove {len(failed)} IP(s). Showing first 10:")
                    for ip, details in failed[:10]:
                        self.log(f"  {ip} -> {details}")
                    if len(failed) > 10:
                        self.log(f"...and {len(failed) - 10} more failures.")
                    messagebox.showwarning(
                        "Some IPs not removed",
                        f"Removed {len(removed)} IP(s), but {len(failed)} failed.\nCheck Log for details."
                    )

                self.refresh_assigned()
            finally:
                self._set_busy(False)

        self._run_in_thread(work, done)

    # ---------------- REMOVE SELECTED ----------------
    def remove_selected(self):
        nic = self.nic_var.get()
        selected = self._get_selected_assigned_ips()
        if not selected:
            messagebox.showinfo("Remove Selected", "No IPs selected.")
            return

        self._set_busy(True)
        self.log(f"Removing {len(selected)} selected IP(s)...")

        def work():
            current_set = set(get_assigned_ips_verify(nic))
            targets = [ip for ip in selected if ip in current_set]
            if not targets:
                return ([], [], [])

            removed = []
            failed = []
            missing = [ip for ip in selected if ip not in current_set]

            for i in range(0, len(targets), BATCH_SIZE):
                batch = targets[i:i + BATCH_SIZE]

                script_lines = [
                    f'interface ipv4 delete address name="{nic}" address={ip}'
                    for ip in batch
                ]
                script_path = self._write_netsh_script(script_lines)

                try:
                    proc = popen_hidden(["netsh", "-f", script_path])
                    out, err = proc.communicate()
                    rc = proc.returncode
                finally:
                    try:
                        os.remove(script_path)
                    except Exception:
                        pass

                after = set(get_assigned_ips_verify(nic))

                for ip in batch:
                    if ip not in after:
                        removed.append(ip)
                    else:
                        details = (err or out or "").strip()
                        if not details:
                            details = f"(netsh rc={rc}, but IP still present after verification)"
                        failed.append((ip, details))

            return (removed, failed, missing)

        def done(result, err):
            try:
                if err:
                    self.log(f"ERROR: {err}")
                    messagebox.showerror("Error", str(err))
                    return

                removed, failed, missing = result

                for ip in removed:
                    self.log(f"Removed: {ip}")
                    self.assigned_checks.pop(ip, None)

                for ip in missing:
                    self.log(f"SKIP (not currently on NIC): {ip}")
                    self.assigned_checks[ip] = False

                if failed:
                    self.log(f"FAILED to remove {len(failed)} IP(s). Showing first 10:")
                    for ip, details in failed[:10]:
                        self.log(f"  {ip} -> {details}")
                    if len(failed) > 10:
                        self.log(f"...and {len(failed) - 10} more failures.")
                    messagebox.showwarning(
                        "Some IPs not removed",
                        f"Removed {len(removed)} IP(s), but {len(failed)} failed.\nCheck Log for details."
                    )
                else:
                    self.log(f"Removed {len(removed)} selected IP(s).")

                self.refresh_assigned()
            finally:
                self._set_busy(False)

        self._run_in_thread(work, done)

    def _write_netsh_script(self, lines):
        tf = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8", suffix=".txt")
        for ln in lines:
            tf.write(ln + "\n")
        tf.close()
        return tf.name

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    IPUtilityApp().run()
